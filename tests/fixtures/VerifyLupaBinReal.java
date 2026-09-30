import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;

public class VerifyLupaBinReal extends ImportLupaBin {
    private boolean cancelAfterWriting;
    private boolean injectionReached;
    private JsonObject before;
    private Path output;
    private String documentHash;

    static class InjectedCancellation extends CancelledException { }

    JsonObject snapshot(List<Entry> entries) throws Exception {
        JsonObject result = new JsonObject();
        JsonObject comments = new JsonObject();
        TreeSet<String> addresses = new TreeSet<>();
        for (Entry entry : entries) if (entry.address != null) addresses.add(entry.address.toString());
        for (String value : addresses) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            String text = currentProgram.getListing().getComment(CommentType.PRE, address);
            comments.add(value, text == null ? JsonNull.INSTANCE : new com.google.gson.JsonPrimitive(text));
        }
        result.add("comments", comments);
        TreeSet<String> bookmarkRows = new TreeSet<>();
        Iterator<Bookmark> iterator = currentProgram.getBookmarkManager().getBookmarksIterator();
        while (iterator.hasNext()) {
            Bookmark bookmark = iterator.next();
            JsonArray row = new JsonArray();
            row.add(bookmark.getAddress().toString());
            row.add(bookmark.getTypeString());
            row.add(bookmark.getCategory());
            row.add(bookmark.getComment());
            bookmarkRows.add(row.toString());
        }
        JsonArray bookmarks = new JsonArray();
        for (String row : bookmarkRows) bookmarks.add(row);
        result.add("bookmarks", bookmarks);
        JsonObject memory = new JsonObject();
        byte[] buffer = new byte[65536];
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) continue;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (long offset = 0; offset < block.getSize();) {
                int size = (int) Math.min(buffer.length, block.getSize() - offset);
                int read = block.getBytes(block.getStart().add(offset), buffer, 0, size);
                require(read == size, "short memory snapshot");
                digest.update(buffer, 0, size);
                offset += size;
            }
            memory.addProperty(block.getStart() + ":" + block.getSize(), HexFormat.of().formatHex(digest.digest()));
        }
        result.add("memory", memory);
        return result;
    }

    void writeNewJson(String name, JsonObject value) throws Exception {
        Files.writeString(output.resolve(name), value.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }

    JsonObject readJsonFile(String name) throws Exception {
        return JsonParser.parseString(Files.readString(output.resolve(name), StandardCharsets.UTF_8)).getAsJsonObject();
    }

    void done(String mode) throws Exception {
        JsonObject result = new JsonObject();
        result.addProperty("phase", mode);
        result.addProperty("ok", true);
        result.addProperty("document_sha256", documentHash);
        result.addProperty("injection_reached", injectionReached);
        writeNewJson(mode + "-result.json", result);
        println("LUPABIN_GHIDRA_" + mode.toUpperCase() + "_OK");
    }

    @Override
    void apply(List<Entry> entries) throws Exception {
        super.apply(entries);
        if (cancelAfterWriting) {
            JsonObject changed = snapshot(entries);
            require(!changed.equals(before), "cancellation injection reached without changes");
            require(changed.get("memory").equals(before.get("memory")), "importer changed mapped bytes");
            injectionReached = true;
            throw new InjectedCancellation();
        }
    }

    @Override
    public void run() throws Exception {
        require(currentProgram != null, "test program missing");
        byte[] raw = Files.readAllBytes(Path.of(getScriptArgs()[0]));
        String mode = getScriptArgs()[1];
        output = Path.of(getScriptArgs()[2]);
        JsonObject document = JsonParser.parseString(new String(raw, StandardCharsets.UTF_8)).getAsJsonObject();
        JsonObject sample = document.getAsJsonObject("report").getAsJsonObject("sample");
        String sha = sample.get("sha256").getAsString();
        long size = sample.get("size").getAsLong();
        documentHash = hash(raw);
        FileBytes original = verifyOriginal(sha, size);
        if (mode.equals("seed")) {
            boolean rejected = false;
            try { verifyOriginal("0".repeat(64), size); }
            catch (Exception expected) { rejected = true; }
            require(rejected, "wrong hash was accepted");
            Map<String, Address> old = new HashMap<>();
            for (Entry entry : prepare(document, original, size, documentHash)) {
                if (entry.status.equals("ready")) old.put(entry.key, entry.address);
            }
            require(!old.isEmpty(), "no mapped annotations before rebase");
            currentProgram.setImageBase(currentProgram.getImageBase().add(0x100000), true);
            List<Entry> plan = prepare(document, original, size, documentHash);
            TreeSet<String> rebasedKeys = new TreeSet<>();
            for (Entry entry : plan) rebasedKeys.add(entry.key);
            require(rebasedKeys.containsAll(old.keySet()), "rebase omitted an annotation key");
            int rvas = 0;
            for (Entry entry : plan) {
                if (old.containsKey(entry.key)) {
                    require(entry.status.equals("ready"), "rebase lost a mapped annotation");
                    require(entry.address.subtract(old.get(entry.key)) == 0x100000, "rebase changed a file mapping");
                }
                if (entry.status.equals("ready") && !entry.source.get("rva").isJsonNull()) {
                    rvas++;
                    require(entry.address.subtract(currentProgram.getImageBase()) == entry.source.get("rva").getAsLong(), "wrong evidence RVA");
                }
            }
            require(rvas > 0, "no mapped RVA annotations");
            String overlay = null;
            for (JsonElement element : document.getAsJsonObject("report").getAsJsonArray("evidence")) {
                JsonObject fact = element.getAsJsonObject();
                if (fact.get("kind").getAsString().equals("string") && fact.getAsJsonObject("data").get("text").getAsString().equals("LUPABIN UNMAPPED OVERLAY")) overlay = fact.get("id").getAsString();
            }
            require(overlay != null, "overlay fixture not exported");
            String overlayKey = overlay + ":0";
            Entry unmapped = plan.stream().filter(e -> e.key.equals(overlayKey)).findFirst().orElseThrow();
            require(unmapped.status.equals("unmapped_or_ambiguous_range") && unmapped.address == null, "overlay mapped unexpectedly");
            TreeSet<Address> seeded = new TreeSet<>();
            for (Entry entry : plan) {
                if (entry.status.equals("ready") && seeded.add(entry.address)) {
                    currentProgram.getListing().setComment(entry.address, CommentType.PRE, "Human annotation retained " + seeded.size());
                    currentProgram.getBookmarkManager().setBookmark(entry.address, "Note", "Human", "Human bookmark retained " + seeded.size());
                    if (seeded.size() == 2) break;
                }
            }
            require(seeded.size() == 2, "not enough human annotation test locations");
            writeNewJson("before.json", snapshot(prepare(document, original, size, documentHash)));
            done(mode);
            return;
        }
        List<Entry> plan = prepare(document, original, size, documentHash);
        before = readJsonFile("before.json");
        if (mode.equals("cancel")) {
            require(snapshot(plan).equals(before), "seed did not persist");
            cancelAfterWriting = true;
            try {
                applyTransaction(document, plan, original, sha, size, documentHash);
            } catch (InjectedCancellation expected) {
                require(injectionReached, "wrong cancellation point");
                done(mode);
                return;
            }
            throw new IllegalStateException("cancellation did not occur");
        }
        if (mode.equals("apply")) {
            require(snapshot(plan).equals(before), "rollback left changes after normal outer commit");
            TreeSet<String> ready = new TreeSet<>();
            for (Entry entry : plan) if (entry.status.equals("ready")) ready.add(entry.key);
            require(!ready.isEmpty(), "no annotations to apply");
            applyTransaction(document, plan, original, sha, size, documentHash);
            JsonObject after = snapshot(plan);
            require(!after.equals(before), "nothing was applied");
            require(after.get("memory").equals(before.get("memory")), "mapped bytes changed");
            for (Map.Entry<String, JsonElement> entry : before.getAsJsonObject("comments").entrySet()) {
                if (!entry.getValue().isJsonNull()) require(after.getAsJsonObject("comments").get(entry.getKey()).getAsString().startsWith(entry.getValue().getAsString()), "human comment changed");
            }
            for (JsonElement bookmark : before.getAsJsonArray("bookmarks")) require(after.getAsJsonArray("bookmarks").contains(bookmark), "human bookmark changed");
            List<Entry> repeated = prepare(document, original, size, documentHash);
            TreeSet<String> repeatedKeys = new TreeSet<>();
            for (Entry entry : repeated) repeatedKeys.add(entry.key);
            require(repeatedKeys.containsAll(ready), "repeat omitted an annotation key");
            for (Entry entry : repeated) if (ready.contains(entry.key)) require(entry.status.equals("already_present"), "repeat not recognized");
            applyTransaction(document, repeated, original, sha, size, documentHash);
            require(snapshot(repeated).equals(after), "repeat changed annotation inventory");
            writeNewJson("after.json", after);
            done(mode);
            return;
        }
        require(mode.equals("persist"), "unknown test mode");
        require(snapshot(plan).equals(readJsonFile("after.json")), "annotation inventory did not persist");
        done(mode);
    }
}
