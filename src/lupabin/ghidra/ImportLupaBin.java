import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

public class ImportLupaBin extends GhidraScript {
    private static final int MAX_JSON = 32 * 1024 * 1024;
    private static final long MAX_CHECK_BYTES = 128L * 1024 * 1024;
    private static final int MAX_COMMENT_CHARS = 65536;
    private static final long MAX_PLAN_CHARS = 16L * 1024 * 1024;
    private static final String NOTICE = "Análisis estático: no demuestra ejecución, intención ni seguridad. " +
        "El hash identifica bytes, no autentica las afirmaciones del informe. " +
        "Revisa report.extractor_runs, extractor_errors y limitations en el JSON original.";

    static class Entry {
        String key;
        String category;
        String text;
        Address address;
        String commentBefore;
        String commentAfter;
        boolean addBookmark;
        String status;
        JsonObject source;
    }

    @Override
    public AnalysisMode getScriptAnalysisMode() {
        return AnalysisMode.DISABLED;
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null || isRunningHeadless()) {
            throw new IOException("Abre un programa en la interfaz de Ghidra; se exige revisión interactiva.");
        }
        Path input = askFile("Selecciona lupabin-ghidra.json", "Abrir").toPath();
        byte[] raw;
        try (InputStream stream = Files.newInputStream(input)) {
            raw = stream.readNBytes(MAX_JSON + 1);
        }
        require(raw.length <= MAX_JSON, "JSON demasiado grande");
        JsonObject document;
        try (JsonReader reader = new JsonReader(new StringReader(decodeUtf8(raw)))) {
            reader.setLenient(false);
            document = readJson(reader, 0).getAsJsonObject();
            require(reader.peek() == JsonToken.END_DOCUMENT, "Contenido tras el JSON");
        }
        require(string(document, "schema_version").equals("1.0.0"), "Versión de exportación no soportada");
        JsonObject report = document.getAsJsonObject("report");
        require(string(report, "schema_version").equals("0.13.0"), "Contrato de hechos no soportado");
        JsonObject sample = report.getAsJsonObject("sample");
        String sha = string(sample, "sha256");
        require(sha.matches("[a-f0-9]{64}"), "SHA-256 inválido");
        long size = integer(sample, "size", 1, 20971520);
        FileBytes original = verifyOriginal(sha, size);
        String documentHash = hash(raw);
        List<Entry> entries = prepare(document, original, size, documentHash);
        JsonObject preview = preview(entries, report, documentHash);
        Path previewPath = askFile("Guardar revisión previa (archivo NUEVO)", "Guardar").toPath();
        writeNew(previewPath, preview);
        long ready = entries.stream().filter(e -> e.status.equals("ready")).count();
        println("LupaBin: revisión guardada. Preparadas: " + ready + "; total: " + entries.size());
        if (ready == 0 || !askYesNo("Revisar LupaBin antes de aplicar", NOTICE + "\n\n" +
                "Se ha guardado la revisión con cada dirección, texto y motivo de abstención.\n" +
                "Lee ese archivo antes de continuar. Preparadas: " + ready + "/" + entries.size() +
                ".\n¿Añadir estas anotaciones sin reemplazar las existentes?")) {
            println("Sin cambios en el programa.");
            return;
        }
        applyTransaction(document, entries, original, sha, size, documentHash);
        println("LupaBin: importación aplicada. Conserva el JSON y su revisión; el programa aún debe guardarse.");
    }

    void applyTransaction(JsonObject document, List<Entry> entries, FileBytes original,
            String sha, long size, String documentHash) throws Exception {
        int transaction = currentProgram.startTransaction("LupaBin: importar evidencias");
        boolean commit = false;
        try {
            verifyOriginal(sha, size);
            List<Entry> checked = prepare(document, original, size, documentHash);
            require(samePlan(entries, checked), "El programa cambió desde la revisión; vuelve a importar");
            apply(entries);
            monitor.checkCancelled();
            commit = true;
        } finally {
            currentProgram.endTransaction(transaction, commit);
        }
    }

    FileBytes verifyOriginal(String sha, long size) throws Exception {
        require(sha.equalsIgnoreCase(currentProgram.getExecutableSHA256()),
            "SHA-256 del programa distinto o no disponible; no se aplica nada");
        List<FileBytes> originals = currentProgram.getMemory().getAllFileBytes();
        require(originals.size() == 1, "Origen del programa ausente o ambiguo");
        FileBytes original = originals.get(0);
        require(original.getFileOffset() == 0 && original.getSize() == size,
            "No se conserva el archivo original completo");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[65536];
        for (long offset = 0; offset < size;) {
            monitor.checkCancelled();
            int count = (int) Math.min(buffer.length, size - offset);
            require(original.getOriginalBytes(offset, buffer, 0, count) == count,
                "No se pudieron leer los bytes originales");
            digest.update(buffer, 0, count);
            offset += count;
        }
        require(sha.equals(HexFormat.of().formatHex(digest.digest())), "Los bytes originales no coinciden");
        return original;
    }

    List<Entry> prepare(JsonObject document, FileBytes original, long size, String digest) throws Exception {
        String analysisStatus = string(document.getAsJsonObject("report").getAsJsonObject("analysis"), "status");
        require(Set.of("completed", "partial", "failed").contains(analysisStatus), "Estado inválido");
        JsonArray facts = document.getAsJsonObject("report").getAsJsonArray("evidence");
        require(facts.size() <= 40000, "Demasiadas evidencias");
        Map<String, JsonObject> byId = new HashMap<>();
        Map<String, String> texts = new HashMap<>();
        Set<String> expected = new HashSet<>();
        long textChars = 0;
        for (JsonElement value : facts) {
            JsonObject fact = value.getAsJsonObject();
            String id = string(fact, "id");
            require(id.matches("E[1-9][0-9]{0,14}") && byId.put(id, fact) == null, "ID inválido o repetido");
            int count = string(fact, "kind").equals("yara_match") ?
                Math.max(1, fact.getAsJsonObject("data").getAsJsonArray("instances").size()) : 1;
            require(count <= 40000 - expected.size(), "Demasiadas instancias");
            for (int i = 0; i < count; i++) expected.add(id + ":" + i);
            String text = factText(fact);
            textChars += text.length();
            require(textChars <= MAX_PLAN_CHARS, "Presupuesto de texto de evidencias agotado");
            texts.put(id, text);
        }
        JsonArray annotations = document.getAsJsonArray("annotations");
        require(annotations.size() <= 40000 && annotations.size() == expected.size(), "Anotaciones incompletas");
        List<Entry> entries = new ArrayList<>();
        Map<Address, String> comments = new HashMap<>();
        long checkedBytes = 0;
        long plannedChars = 0;
        long annotationChars = 0;
        for (JsonElement value : annotations) {
            monitor.checkCancelled();
            Entry entry = new Entry();
            entry.source = value.getAsJsonObject();
            entry.key = string(entry.source, "key");
            require(expected.remove(entry.key), "Clave de anotación inválida o repetida");
            String id = string(entry.source, "evidence_id");
            JsonObject fact = byId.get(id);
            require(fact != null && entry.key.startsWith(id + ":"), "Referencia de evidencia inválida");
            validateLocation(entry.source, fact);
            entry.category = "LupaBin/" + digest + "/" + entry.key;
            String text = string(entry.source, "text");
            require(text.length() <= 8192, "Texto de anotación demasiado largo");
            entry.text = "[" + entry.category + "]\n" + texts.get(id) +
                "\n" + NOTICE + "\nEstado del análisis: " + analysisStatus;
            require(entry.text.length() <= 12000, "Texto de anotación demasiado largo");
            annotationChars += entry.text.length();
            require(annotationChars <= MAX_PLAN_CHARS, "Presupuesto de texto de anotaciones agotado");
            if (isNull(entry.source, "offset") || isNull(entry.source, "length")) {
                entry.status = "location_unavailable";
            } else {
                long offset = integer(entry.source, "offset", 0, size - 1);
                int length = (int) integer(entry.source, "length", 1, size - offset);
                if (checkedBytes + length > MAX_CHECK_BYTES) {
                    entry.status = "verification_budget";
                } else {
                    checkedBytes += length;
                    entry.address = resolve(offset, length, original);
                    entry.status = entry.address == null ? "unmapped_or_ambiguous_range" : "ready";
                    if (entry.address != null && !isNull(entry.source, "rva")) {
                        long rva = integer(entry.source, "rva", 0, 0xffffffffL);
                        if (!entry.address.equals(currentProgram.getImageBase().addNoWrap(rva))) {
                            entry.status = "rva_mapping_mismatch";
                        }
                    }
                    if (entry.status.equals("ready")) {
                        String rangeHash = string(entry.source, "range_sha256");
                        require(rangeHash.matches("[a-f0-9]{64}"), "Hash de rango inválido");
                        byte[] bytes = new byte[length];
                        require(original.getOriginalBytes(offset, bytes) == length, "Rango original ilegible");
                        require(hash(bytes).equals(rangeHash), "Hash de rango distinto al archivo original");
                        if (currentProgram.getMemory().getBytes(entry.address, bytes) != length ||
                                !hash(bytes).equals(rangeHash)) {
                            entry.status = "modified_memory_bytes";
                        }
                    }
                }
            }
            if (entry.status.equals("ready")) {
                planAnnotations(entry, comments, MAX_PLAN_CHARS - plannedChars);
                if (entry.commentAfter != null) plannedChars += entry.commentAfter.length();
            }
            entries.add(entry);
        }
        return entries;
    }

    void validateLocation(JsonObject annotation, JsonObject fact) throws IOException {
        require(string(annotation, "kind").equals(string(fact, "kind")) &&
            string(annotation, "confidence").equals(string(fact, "confidence")), "Tipo o confianza alterados");
        require(Set.of("observed", "inferred").contains(string(annotation, "confidence")), "Confianza inválida");
        JsonObject location;
        String lengthKey = "length";
        if (string(fact, "kind").equals("yara_match")) {
            JsonArray instances = fact.getAsJsonObject("data").getAsJsonArray("instances");
            int index = Integer.parseInt(string(annotation, "key").split(":")[1]);
            location = instances.size() == 0 ? null : instances.get(index).getAsJsonObject();
            lengthKey = "matched_length";
            require(isNull(annotation, "rva"), "YARA no declara RVA");
        } else {
            location = isNull(fact, "location") ? null : fact.getAsJsonObject("location");
            require(equalField(annotation, "rva", location, "rva"), "RVA alterada");
        }
        require(equalField(annotation, "offset", location, "offset") &&
            equalField(annotation, "length", location, lengthKey), "Rango de evidencia alterado");
    }

    Address resolve(long offset, int length, FileBytes original) throws Exception {
        Address found = null;
        int overlaps = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
                if (!source.getFileBytes().filter(original::equals).isPresent()) continue;
                long start = source.getFileBytesOffset();
                if (start < 0 || offset >= start + source.getLength() || offset + length <= start) continue;
                overlaps++;
                if (!block.isInitialized() || block.isMapped() || block.isOverlay() ||
                        offset < start || offset + length > start + source.getLength()) continue;
                Address address = source.getMinAddress().addNoWrap(offset - start);
                Address end = address.addNoWrap(length - 1);
                if (source.contains(end) && source.getFileBytesOffset(address) == offset &&
                        source.getFileBytesOffset(end) == offset + length - 1 &&
                        address.getAddressSpace().equals(currentProgram.getImageBase().getAddressSpace())) {
                    found = address;
                }
            }
        }
        return overlaps == 1 ? found : null;
    }

    void planAnnotations(Entry entry, Map<Address, String> comments, long remaining) {
        Listing listing = currentProgram.getListing();
        String before = comments.containsKey(entry.address) ? comments.get(entry.address) :
            listing.getComment(CommentType.PRE, entry.address);
        if (before != null && (before.length() > MAX_COMMENT_CHARS || before.length() > remaining)) {
            entry.status = "annotation_budget";
            return;
        }
        entry.commentBefore = before;
        String marker = "[" + entry.category + "]";
        if (before != null && before.contains(marker)) {
            if (!(before.equals(entry.text) || before.startsWith(entry.text + "\n") ||
                    before.endsWith("\n" + entry.text) || before.contains("\n" + entry.text + "\n"))) {
                entry.status = "existing_comment_conflict";
                return;
            }
            entry.commentAfter = before;
        } else {
            long length = (before == null || before.isEmpty() ? 0L : before.length() + 1L) + entry.text.length();
            if (length > MAX_COMMENT_CHARS || length > remaining) {
                entry.status = "annotation_budget";
                return;
            }
            entry.commentAfter = before == null || before.isEmpty() ? entry.text : before + "\n" + entry.text;
        }
        Bookmark bookmark = currentProgram.getBookmarkManager().getBookmark(entry.address, "Note", entry.category);
        if (bookmark != null && !entry.text.equals(bookmark.getComment())) {
            entry.status = "existing_bookmark_conflict";
            return;
        }
        entry.addBookmark = bookmark == null;
        if (!entry.addBookmark && java.util.Objects.equals(entry.commentBefore, entry.commentAfter)) {
            entry.status = "already_present";
        }
        comments.put(entry.address, entry.commentAfter);
    }

    void apply(List<Entry> entries) throws Exception {
        Listing listing = currentProgram.getListing();
        BookmarkManager bookmarks = currentProgram.getBookmarkManager();
        for (Entry entry : entries) {
            monitor.checkCancelled();
            if (!entry.status.equals("ready")) continue;
            require(java.util.Objects.equals(entry.commentBefore, listing.getComment(CommentType.PRE, entry.address)),
                "Comentario modificado desde la revisión");
            if (!java.util.Objects.equals(entry.commentBefore, entry.commentAfter)) {
                listing.setComment(entry.address, CommentType.PRE, entry.commentAfter);
                require(java.util.Objects.equals(entry.commentAfter, listing.getComment(CommentType.PRE, entry.address)),
                    "Ghidra no conservó el comentario; se revierte la importación");
            }
            if (entry.addBookmark) {
                require(bookmarks.getBookmark(entry.address, "Note", entry.category) == null,
                    "Marcador modificado desde la revisión");
                bookmarks.setBookmark(entry.address, "Note", entry.category, entry.text);
            }
        }
    }

    static boolean samePlan(List<Entry> before, List<Entry> after) {
        if (before.size() != after.size()) return false;
        for (int i = 0; i < before.size(); i++) {
            Entry a = before.get(i), b = after.get(i);
            if (!a.status.equals(b.status) || !java.util.Objects.equals(a.address, b.address) ||
                    !java.util.Objects.equals(a.commentBefore, b.commentBefore) ||
                    !java.util.Objects.equals(a.commentAfter, b.commentAfter) || a.addBookmark != b.addBookmark) return false;
        }
        return true;
    }

    JsonObject preview(List<Entry> entries, JsonObject report, String digest) {
        JsonObject preview = new JsonObject();
        preview.addProperty("schema_version", "1.0.0");
        preview.addProperty("document_sha256", digest);
        preview.addProperty("notice", NOTICE);
        preview.addProperty("applied", false);
        preview.addProperty("purpose", "Revisión previa; no acredita que se haya aplicado la importación");
        preview.add("analysis", report.get("analysis"));
        preview.add("extractor_runs", report.get("extractor_runs"));
        preview.add("extractor_errors", report.get("extractor_errors"));
        preview.add("limitations", report.get("limitations"));
        JsonArray items = new JsonArray();
        for (Entry entry : entries) {
            JsonObject item = new JsonObject();
            item.addProperty("key", entry.key);
            item.addProperty("status", entry.status);
            item.addProperty("address", entry.status.equals("ready") || entry.status.equals("already_present") ?
                entry.address.toString() : null);
            item.add("offset", entry.source.get("offset"));
            item.add("length", entry.source.get("length"));
            item.add("rva", entry.source.get("rva"));
            item.addProperty("text", entry.text);
            items.add(item);
        }
        preview.add("entries", items);
        return preview;
    }

    static void writeNew(Path path, JsonObject value) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            new GsonBuilder().setPrettyPrinting().create().toJson(value, writer);
        }
    }

    static String factText(JsonObject fact) throws IOException {
        String kind = string(fact, "kind");
        require(kind.matches("[a-z_]{1,64}"), "Tipo de evidencia inválido");
        require(!isNull(fact, "data"), "Datos de evidencia ausentes");
        String serialized = fact.getAsJsonObject("data").toString();
        boolean truncated = serialized.length() > 4096;
        String payload = safe(truncated ? serialized.substring(0, 4096) : serialized);
        if (truncated || payload.length() > 4096) {
            payload = payload.substring(0, Math.min(4096, payload.length())) +
                " [texto abreviado; datos íntegros en report.evidence]";
        }
        String text = string(fact, "id") + " | " + kind + " | " + string(fact, "confidence") + "\n" + payload;
        JsonArray ids = fact.getAsJsonObject("provenance").getAsJsonArray("evidence_ids");
        StringBuilder provenance = new StringBuilder();
        for (JsonElement id : ids) {
            require(id.isJsonPrimitive() && id.getAsJsonPrimitive().isString() &&
                id.getAsString().matches("E[1-9][0-9]{0,14}"), "Procedencia inválida");
            if (provenance.length() != 0) provenance.append(", ");
            provenance.append(id.getAsString());
            require(provenance.length() <= 4096, "Procedencia demasiado larga");
        }
        text += "\nProcedencia: " + provenance;
        if (kind.equals("decoded_string")) {
            text += "\nUbicación de los bytes codificados, no del texto resultante en memoria.";
        }
        return text;
    }

    static String safe(String value) {
        StringBuilder text = new StringBuilder();
        value.codePoints().forEach(c -> {
            if ((c < 32 && c != 10) || c >= 127 && c <= 159 || Character.getType(c) == Character.FORMAT ||
                    Character.getType(c) == Character.PRIVATE_USE || Character.getType(c) == Character.SURROGATE ||
                    c == 0x2028 || c == 0x2029 || c == '{' || c == '}') {
                text.append(String.format("⟨U+%04X⟩", c));
            } else text.appendCodePoint(c);
        });
        return text.toString();
    }

    static boolean isNull(JsonObject value, String key) {
        return value == null || !value.has(key) || value.get(key).isJsonNull();
    }

    static boolean equalField(JsonObject a, String ak, JsonObject b, String bk) {
        return isNull(a, ak) ? isNull(b, bk) : !isNull(b, bk) && a.get(ak).equals(b.get(bk));
    }

    static String string(JsonObject value, String key) throws IOException {
        require(!isNull(value, key) && value.get(key).isJsonPrimitive() &&
            value.getAsJsonPrimitive(key).isString(), "Campo de texto inválido: " + key);
        return value.get(key).getAsString();
    }

    static long integer(JsonObject value, String key, long min, long max) throws IOException {
        require(!isNull(value, key) && value.get(key).isJsonPrimitive() &&
            value.getAsJsonPrimitive(key).isNumber(), "Entero inválido: " + key);
        String raw = value.get(key).getAsString();
        require(raw.matches("0|[1-9][0-9]{0,18}"), "Entero no canónico: " + key);
        long number = Long.parseLong(raw);
        require(number >= min && number <= max, "Entero fuera de rango: " + key);
        return number;
    }

    static String decodeUtf8(byte[] bytes) throws IOException {
        return StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString();
    }

    static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }

    static JsonElement readJson(JsonReader reader, int depth) throws IOException {
        require(depth <= 64, "JSON demasiado profundo");
        switch (reader.peek()) {
            case BEGIN_OBJECT:
                JsonObject object = new JsonObject();
                reader.beginObject();
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    require(!object.has(key), "Clave JSON repetida");
                    object.add(key, readJson(reader, depth + 1));
                }
                reader.endObject();
                return object;
            case BEGIN_ARRAY:
                JsonArray array = new JsonArray();
                reader.beginArray();
                while (reader.hasNext()) {
                    require(array.size() < 100000, "Array JSON demasiado grande");
                    array.add(readJson(reader, depth + 1));
                }
                reader.endArray();
                return array;
            case STRING:
                return new JsonPrimitive(reader.nextString());
            case NUMBER:
                String number = reader.nextString();
                require(number.length() <= 64, "Número JSON demasiado largo");
                return new JsonPrimitive(new java.math.BigDecimal(number));
            case BOOLEAN:
                return new JsonPrimitive(reader.nextBoolean());
            case NULL:
                reader.nextNull();
                return JsonNull.INSTANCE;
            default:
                throw new IOException("JSON inválido");
        }
    }
}
