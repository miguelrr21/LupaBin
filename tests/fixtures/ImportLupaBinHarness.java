import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import com.google.gson.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class ImportLupaBinHarness {
    static final long BASE = 0x180000000L;
    static final String DIGEST = "a".repeat(64);
    static int tests = 0;

    static void check(boolean condition) {
        if (!condition) throw new AssertionError();
    }

    interface Action { void run() throws Exception; }

    static void refused(Action action) throws Exception {
        boolean failed = false;
        try { action.run(); } catch (Exception expected) { failed = true; }
        check(failed);
    }

    static ImportLupaBin importer() throws Exception {
        ImportLupaBin script = new ImportLupaBin();
        Program program = new Program();
        byte[] data = new byte[1024];
        for (int i=0;i<data.length;i++) data[i]=(byte)i;
        FileBytes file = new FileBytes(data);
        program.memory.files.add(file);
        MemoryBlock block = new MemoryBlock();
        block.sources.add(new MemoryBlockSourceInfo(file,512,128,BASE+4096));
        program.memory.blocks.add(block);
        program.sha=ImportLupaBin.hash(data);
        script.currentProgram=program;
        return script;
    }

    static JsonObject location(long offset,long length,Long rva) {
        JsonObject loc=new JsonObject();
        loc.addProperty("offset",offset);
        loc.addProperty("length",length);
        if (rva!=null) loc.addProperty("rva",rva);
        return loc;
    }

    static JsonObject document(ImportLupaBin script,int count) throws Exception {
        JsonObject doc=new JsonObject(), report=new JsonObject(), analysis=new JsonObject();
        analysis.addProperty("status","partial");
        report.add("analysis",analysis);
        JsonArray facts=new JsonArray(), annotations=new JsonArray();
        for (int i=1;i<=count;i++) {
            JsonObject fact=new JsonObject(), annotation=location(520,4,4104L);
            fact.addProperty("id","E"+i);
            fact.addProperty("kind","api_call");
            fact.addProperty("confidence","observed");
            fact.add("location",location(520,4,4104L));
            JsonObject data=new JsonObject(), provenance=new JsonObject();
            data.addProperty("value","payload hostile {@url evil} \u001b[31m");
            provenance.add("evidence_ids",new JsonArray());
            fact.add("data",data);
            fact.add("provenance",provenance);
            facts.add(fact);
            annotation.addProperty("key","E"+i+":0");
            annotation.addProperty("evidence_id","E"+i);
            annotation.addProperty("kind","api_call");
            annotation.addProperty("confidence","observed");
            annotation.addProperty("text","E"+i+" hostile {@url evil} \u001b[31m");
            annotation.addProperty("range_sha256",ImportLupaBin.hash(Arrays.copyOfRange(
                script.currentProgram.memory.files.get(0).data,520,524)));
            annotations.add(annotation);
        }
        report.add("evidence",facts);
        doc.add("report",report);
        doc.add("annotations",annotations);
        return doc;
    }

    static List<ImportLupaBin.Entry> prepare(ImportLupaBin s,JsonObject d) throws Exception {
        return s.prepare(d,s.currentProgram.memory.files.get(0),1024,DIGEST);
    }

    static void apply(ImportLupaBin s,JsonObject d,List<ImportLupaBin.Entry> plan) throws Exception {
        s.applyTransaction(d,plan,s.currentProgram.memory.files.get(0),s.currentProgram.sha,1024,DIGEST);
    }

    static void hashes() throws Exception {
        ImportLupaBin s=importer();
        check(s.verifyOriginal(s.currentProgram.sha,1024)!=null);
        refused(()->s.verifyOriginal("f".repeat(64),1024));
        String sha=s.currentProgram.sha;
        s.currentProgram.memory.files.get(0).data[0]^=1;
        refused(()->s.verifyOriginal(sha,1024));
        s.currentProgram.sha=null;
        refused(()->s.verifyOriginal(sha,1024));
        s.currentProgram.memory.files.clear();
        refused(()->s.verifyOriginal(sha,1024));
        tests++;
    }

    static void mapping() throws Exception {
        ImportLupaBin s=importer();
        FileBytes file=s.currentProgram.memory.files.get(0);
        check(s.resolve(520,4,file).equals(new Address(BASE+4104)));
        check(s.resolve(520,4,file).value!=BASE+520);
        check(s.resolve(1000,4,file)==null);
        check(s.resolve(630,20,file)==null);
        JsonObject d=document(s,1);
        check(prepare(s,d).get(0).status.equals("ready"));
        s.currentProgram.base=new Address(BASE+0x10000);
        check(prepare(s,d).get(0).status.equals("rva_mapping_mismatch"));
        s.currentProgram.memory.blocks.get(0).sources.get(0).address=new Address(BASE+0x10000+4096);
        check(prepare(s,d).get(0).status.equals("ready"));
        s.currentProgram.memory.blocks.add(s.currentProgram.memory.blocks.get(0));
        check(s.resolve(520,4,file)==null);
        tests++;
    }

    static void patches() throws Exception {
        ImportLupaBin s=importer();
        JsonObject d=document(s,1);
        s.currentProgram.memory.patched=true;
        check(prepare(s,d).get(0).status.equals("modified_memory_bytes"));
        s.currentProgram.memory.patched=false;
        d.getAsJsonArray("annotations").get(0).getAsJsonObject().addProperty("range_sha256","0".repeat(64));
        refused(()->prepare(s,d));
        JsonObject valid=document(s,1);
        s.currentProgram.listing.comments.put(new Address(BASE+4104),"X".repeat(65536));
        check(prepare(s,valid).get(0).status.equals("annotation_budget"));
        check(s.currentProgram.listing.comments.get(new Address(BASE+4104)).length()==65536);
        valid.getAsJsonArray("annotations").get(0).getAsJsonObject().addProperty("text","X".repeat(8193));
        refused(()->prepare(s,valid));
        tests++;
    }

    static void noOverwriteAndRepeat() throws Exception {
        ImportLupaBin s=importer();
        JsonObject d=document(s,2);
        Address address=new Address(BASE+4104);
        s.currentProgram.listing.comments.put(address,"Human annotation\nkeep byte-for-byte");
        s.currentProgram.bookmarks.setBookmark(address,"Note","Human","My bookmark");
        List<ImportLupaBin.Entry> plan=prepare(s,d);
        check(!plan.get(0).text.contains("{@") && !plan.get(0).text.contains("\u001b"));
        apply(s,d,plan);
        check(s.currentProgram.committed);
        String before=s.currentProgram.listing.comments.get(address);
        check(before.startsWith("Human annotation\nkeep byte-for-byte\n"));
        check(s.currentProgram.bookmarks.items.size()==3);
        List<ImportLupaBin.Entry> again=prepare(s,d);
        check(again.stream().allMatch(e->e.status.equals("already_present")));
        apply(s,d,again);
        check(before.equals(s.currentProgram.listing.comments.get(address)));
        check(s.currentProgram.bookmarks.items.size()==3);
        s.currentProgram.bookmarks.getBookmark(address,"Note",plan.get(0).category).text="Human edit";
        check(prepare(s,d).get(0).status.equals("existing_bookmark_conflict"));
        check(s.currentProgram.bookmarks.getBookmark(address,"Note","Human").text.equals("My bookmark"));
        tests++;
    }

    static void rollback() throws Exception {
        ImportLupaBin s=importer();
        JsonObject d=document(s,2);
        List<ImportLupaBin.Entry> plan=prepare(s,d);
        s.currentProgram.bookmarks.remaining=1;
        refused(()->apply(s,d,plan));
        check(!s.currentProgram.committed);
        check(s.currentProgram.listing.comments.isEmpty());
        check(s.currentProgram.bookmarks.items.isEmpty());
        s.currentProgram.bookmarks.remaining=Integer.MAX_VALUE;
        s.monitor.remaining=4;
        refused(()->apply(s,d,plan));
        check(s.currentProgram.listing.comments.isEmpty());
        check(s.currentProgram.bookmarks.items.isEmpty());
        tests++;
    }

    static void changedSinceReview() throws Exception {
        ImportLupaBin s=importer();
        JsonObject d=document(s,1);
        List<ImportLupaBin.Entry> plan=prepare(s,d);
        Address address=new Address(BASE+4104);
        s.currentProgram.listing.comments.put(address,"Human added after review");
        refused(()->apply(s,d,plan));
        check(s.currentProgram.listing.comments.get(address).equals("Human added after review"));
        check(s.currentProgram.bookmarks.items.isEmpty());
        tests++;
    }

    static void invalidLocations() throws Exception {
        ImportLupaBin s=importer();
        JsonObject d=document(s,1);
        JsonObject a=d.getAsJsonArray("annotations").get(0).getAsJsonObject();
        a.addProperty("offset",0);
        refused(()->prepare(s,d));
        a.addProperty("offset",520L);
        a.addProperty("rva",nullString());
        refused(()->prepare(s,d));
        JsonObject fact=d.getAsJsonObject("report").getAsJsonArray("evidence").get(0).getAsJsonObject();
        fact.add("location",JsonNull.INSTANCE);
        a.add("offset",JsonNull.INSTANCE);
        a.add("length",JsonNull.INSTANCE);
        List<ImportLupaBin.Entry> p=prepare(s,d);
        check(p.get(0).status.equals("location_unavailable") && p.get(0).address==null);
        tests++;
    }

    static String nullString() { return null; }

    static void previewFile(Path directory) throws Exception {
        Path p=directory.resolve("preview.json");
        Files.writeString(p,"existing human file");
        refused(()->ImportLupaBin.writeNew(p,new JsonObject()));
        check(Files.readString(p).equals("existing human file"));
        tests++;
    }

    static void textIsDerivedFromFact() throws Exception {
        refused(()->ImportLupaBin.decodeUtf8(new byte[]{(byte)0xc0,(byte)0xaf}));
        check(ImportLupaBin.decodeUtf8(new byte[]{65}).equals("A"));
        ImportLupaBin s=importer();
        JsonObject d=document(s,1);
        d.getAsJsonArray("annotations").get(0).getAsJsonObject().addProperty("text","Invented conclusion {@exec evil}");
        String text=prepare(s,d).get(0).text;
        check(!text.contains("Invented conclusion") && text.contains("payload hostile"));
        check(!text.contains("{@") && !text.contains("\u001b"));
        d.getAsJsonObject("report").getAsJsonArray("evidence").get(0).getAsJsonObject().addProperty("kind","{@url evil}");
        refused(()->prepare(s,d));
        tests++;
    }

    static void repeatAtCommentLimit() throws Exception {
        ImportLupaBin s=importer();
        JsonObject d=document(s,1);
        Address address=new Address(BASE+4104);
        int length=prepare(s,d).get(0).text.length();
        s.currentProgram.listing.comments.put(address,"H".repeat(65536-length-1));
        List<ImportLupaBin.Entry> plan=prepare(s,d);
        check(plan.get(0).status.equals("ready"));
        apply(s,d,plan);
        String before=s.currentProgram.listing.comments.get(address);
        check(before.length()==65536);
        check(prepare(s,d).get(0).status.equals("already_present"));
        check(before.equals(s.currentProgram.listing.comments.get(address)));
        ImportLupaBin.Entry limited=prepare(s,d).get(0);
        limited.status="ready";
        s.planAnnotations(limited,new java.util.HashMap<>(),65535);
        check(limited.status.equals("annotation_budget"));
        tests++;
    }

    static void independentReports() throws Exception {
        ImportLupaBin s=importer();
        JsonObject first=document(s,1);
        apply(s,first,prepare(s,first));
        JsonObject second=document(s,1);
        JsonObject fact=second.getAsJsonObject("report").getAsJsonArray("evidence").get(0).getAsJsonObject();
        fact.addProperty("id","E99");
        JsonObject annotation=second.getAsJsonArray("annotations").get(0).getAsJsonObject();
        annotation.addProperty("key","E99:0");
        annotation.addProperty("evidence_id","E99");
        String other="b".repeat(64);
        FileBytes file=s.currentProgram.memory.files.get(0);
        List<ImportLupaBin.Entry> plan=s.prepare(second,file,1024,other);
        check(plan.get(0).status.equals("ready"));
        s.applyTransaction(second,plan,file,s.currentProgram.sha,1024,other);
        check(s.currentProgram.bookmarks.items.size()==2);
        check(prepare(s,first).get(0).status.equals("already_present"));
        check(s.prepare(second,file,1024,other).get(0).status.equals("already_present"));
        s.currentProgram.bookmarks.getBookmark(plan.get(0).address,"Note",plan.get(0).category).text="Human edit";
        check(s.prepare(second,file,1024,other).get(0).status.equals("existing_bookmark_conflict"));
        check(prepare(s,first).get(0).status.equals("already_present"));
        tests++;
    }

    static void realJsonParser() throws Exception {
        try (var reader=new com.google.gson.stream.JsonReader(new java.io.StringReader("{\"a\":1,\"a\":2}"))) {
            refused(()->ImportLupaBin.readJson(reader,0));
        }
        try (var reader=new com.google.gson.stream.JsonReader(new java.io.StringReader("[".repeat(66)+"0"+"]".repeat(66)))) {
            refused(()->ImportLupaBin.readJson(reader,0));
        }
        try (var reader=new com.google.gson.stream.JsonReader(new java.io.StringReader("{\"a\":1}"))) {
            check(ImportLupaBin.integer(ImportLupaBin.readJson(reader,0).getAsJsonObject(),"a",0,2)==1);
        }
        tests++;
    }

    public static void main(String[] args) throws Exception {
        hashes(); mapping(); patches(); noOverwriteAndRepeat(); rollback(); changedSinceReview();
        invalidLocations(); previewFile(Path.of(args[0]));
        textIsDerivedFromFact(); repeatAtCommentLimit(); independentReports();
        if (args.length>1) realJsonParser();
        check(importer().getScriptAnalysisMode()==ghidra.app.script.GhidraScript.AnalysisMode.DISABLED);
        System.out.println("MOCK_ONLY: "+tests+" checks passed; no real Ghidra execution");
    }
}
