STUBS = {
    "com/google/gson/JsonElement.java": """
package com.google.gson;
public class JsonElement {
    public JsonObject getAsJsonObject() { return (JsonObject)this; }
    public JsonArray getAsJsonArray() { return (JsonArray)this; }
    public JsonPrimitive getAsJsonPrimitive() { return (JsonPrimitive)this; }
    public boolean isJsonNull() { return this instanceof JsonNull; }
    public boolean isJsonPrimitive() { return this instanceof JsonPrimitive; }
    public String getAsString() { return ((JsonPrimitive)this).value.toString(); }
}
""",
    "com/google/gson/JsonNull.java": """
package com.google.gson;
public class JsonNull extends JsonElement {
    public static final JsonNull INSTANCE = new JsonNull();
}
""",
    "com/google/gson/JsonPrimitive.java": """
package com.google.gson;
public class JsonPrimitive extends JsonElement {
    Object value;
    public JsonPrimitive(String x) { value=x; }
    public JsonPrimitive(Number x) { value=x; }
    public JsonPrimitive(Boolean x) { value=x; }
    public boolean isString() { return value instanceof String; }
    public boolean isNumber() { return value instanceof Number; }
    public String toString() { return value.toString(); }
    public boolean equals(Object x) {
        return x instanceof JsonPrimitive && value.equals(((JsonPrimitive)x).value);
    }
}
""",
    "com/google/gson/JsonObject.java": """
package com.google.gson;
public class JsonObject extends JsonElement {
    java.util.Map<String,JsonElement> data = new java.util.HashMap<>();
    public void add(String k, JsonElement v) { data.put(k,v == null ? JsonNull.INSTANCE : v); }
    public void addProperty(String k, String v) { add(k,v==null?null:new JsonPrimitive(v)); }
    public void addProperty(String k, Number v) { add(k,new JsonPrimitive(v)); }
    public void addProperty(String k, Boolean v) { add(k,new JsonPrimitive(v)); }
    public JsonElement get(String k) { return data.get(k); }
    public boolean has(String k) { return data.containsKey(k); }
    public JsonObject getAsJsonObject(String k) { return (JsonObject)get(k); }
    public JsonArray getAsJsonArray(String k) { return (JsonArray)get(k); }
    public JsonPrimitive getAsJsonPrimitive(String k) { return (JsonPrimitive)get(k); }
    public String toString() { return data.toString(); }
}
""",
    "com/google/gson/JsonArray.java": """
package com.google.gson;
public class JsonArray extends JsonElement implements Iterable<JsonElement> {
    java.util.List<JsonElement> data = new java.util.ArrayList<>();
    public void add(JsonElement x) { data.add(x); }
    public int size() { return data.size(); }
    public JsonElement get(int i) { return data.get(i); }
    public java.util.Iterator<JsonElement> iterator() { return data.iterator(); }
}
""",
    "com/google/gson/GsonBuilder.java": """
package com.google.gson;
public class GsonBuilder {
    public GsonBuilder setPrettyPrinting() { return this; }
    public GsonBuilder create() { return this; }
    public void toJson(JsonObject x, java.io.Writer w) throws java.io.IOException { w.write("{}"); }
}
""",
    "com/google/gson/stream/JsonToken.java": """
package com.google.gson.stream;
public enum JsonToken { BEGIN_OBJECT, BEGIN_ARRAY, STRING, NUMBER, BOOLEAN, NULL, END_DOCUMENT }
""",
    "com/google/gson/stream/JsonReader.java": """
package com.google.gson.stream;
public class JsonReader implements AutoCloseable {
    public JsonReader(java.io.Reader r) {}
    public void setLenient(boolean v) {}
    public JsonToken peek() { throw new UnsupportedOperationException("Parser not mocked"); }
    public void beginObject() {}
    public void endObject() {}
    public void beginArray() {}
    public void endArray() {}
    public boolean hasNext() { return false; }
    public String nextName() { return null; }
    public String nextString() { return null; }
    public boolean nextBoolean() { return false; }
    public void nextNull() {}
    public void close() {}
}
""",
    "ghidra/app/script/GhidraScript.java": """
package ghidra.app.script;
public abstract class GhidraScript {
    public ghidra.program.model.listing.Program currentProgram;
    public Monitor monitor = new Monitor();
    public enum AnalysisMode { ENABLED, DISABLED }
    public AnalysisMode getScriptAnalysisMode() { return AnalysisMode.ENABLED; }
    public abstract void run() throws Exception;
    public boolean isRunningHeadless() { return false; }
    public java.io.File askFile(String a, String b) { throw new UnsupportedOperationException(); }
    public boolean askYesNo(String a, String b) { throw new UnsupportedOperationException(); }
    public void println(String text) {}
    public static class Monitor {
        public int remaining = Integer.MAX_VALUE;
        public void checkCancelled() throws Exception {
            if (--remaining < 0) throw new Exception("cancelled");
        }
    }
}
""",
    "ghidra/program/model/address/Address.java": """
package ghidra.program.model.address;
public class Address {
    public long value;
    public Address(long v) { value=v; }
    public Address addNoWrap(long n) { return new Address(Math.addExact(value,n)); }
    public Object getAddressSpace() { return "ram"; }
    public boolean equals(Object x) { return x instanceof Address && ((Address)x).value==value; }
    public int hashCode() { return Long.hashCode(value); }
    public String toString() { return Long.toHexString(value); }
}
""",
    "ghidra/program/database/mem/FileBytes.java": """
package ghidra.program.database.mem;
public class FileBytes {
    public byte[] data;
    public long offset=0;
    public FileBytes(byte[] d) { data=d; }
    public long getFileOffset() { return offset; }
    public long getSize() { return data.length; }
    public int getOriginalBytes(long p, byte[] b) { return getOriginalBytes(p,b,0,b.length); }
    public int getOriginalBytes(long p, byte[] b, int off, int count) {
        System.arraycopy(data,(int)p,b,off,count); return count;
    }
}
""",
    "ghidra/program/model/mem/MemoryBlockSourceInfo.java": """
package ghidra.program.model.mem;
import ghidra.program.model.address.Address;
import ghidra.program.database.mem.FileBytes;
public class MemoryBlockSourceInfo {
    public FileBytes file;
    public long offset, length;
    public Address address;
    public MemoryBlockSourceInfo(FileBytes f,long o,long l,long a) {
        file=f; offset=o; length=l; address=new Address(a);
    }
    public java.util.Optional<FileBytes> getFileBytes() { return java.util.Optional.of(file); }
    public long getFileBytesOffset() { return offset; }
    public long getFileBytesOffset(Address a) { return offset + a.value-address.value; }
    public long getLength() { return length; }
    public Address getMinAddress() { return address; }
    public boolean contains(Address a) {
        return a.value>=address.value && a.value<address.value+length;
    }
}
""",
    "ghidra/program/model/mem/MemoryBlock.java": """
package ghidra.program.model.mem;
public class MemoryBlock {
    public java.util.List<MemoryBlockSourceInfo> sources = new java.util.ArrayList<>();
    public boolean initialized=true, mapped=false, overlay=false;
    public java.util.List<MemoryBlockSourceInfo> getSourceInfos() { return sources; }
    public boolean isInitialized() { return initialized; }
    public boolean isMapped() { return mapped; }
    public boolean isOverlay() { return overlay; }
}
""",
    "ghidra/program/model/mem/Memory.java": """
package ghidra.program.model.mem;
import ghidra.program.model.address.Address;
import ghidra.program.database.mem.FileBytes;
public class Memory {
    public java.util.List<FileBytes> files = new java.util.ArrayList<>();
    public java.util.List<MemoryBlock> blocks = new java.util.ArrayList<>();
    public boolean patched=false;
    public java.util.List<FileBytes> getAllFileBytes() { return files; }
    public MemoryBlock[] getBlocks() { return blocks.toArray(new MemoryBlock[0]); }
    public int getBytes(Address a, byte[] b) {
        for (MemoryBlock block: blocks) for (MemoryBlockSourceInfo source: block.sources) {
            if (source.contains(a)) {
                int n = source.file.getOriginalBytes(source.getFileBytesOffset(a),b);
                if (patched) b[0]^=1;
                return n;
            }
        }
        return 0;
    }
}
""",
    "ghidra/program/model/listing/CommentType.java": """
package ghidra.program.model.listing;
public enum CommentType { PRE }
""",
    "ghidra/program/model/listing/Listing.java": """
package ghidra.program.model.listing;
import ghidra.program.model.address.Address;
public class Listing {
    public java.util.Map<Address,String> comments = new java.util.HashMap<>();
    public String getComment(CommentType t,Address a) { return comments.get(a); }
    public void setComment(Address a,CommentType t,String c) { comments.put(a,c); }
}
""",
    "ghidra/program/model/listing/Bookmark.java": """
package ghidra.program.model.listing;
public class Bookmark {
    public String text;
    public Bookmark(String t) { text=t; }
    public String getComment() { return text; }
}
""",
    "ghidra/program/model/listing/BookmarkManager.java": """
package ghidra.program.model.listing;
import ghidra.program.model.address.Address;
public class BookmarkManager {
    public java.util.Map<String,Bookmark> items = new java.util.HashMap<>();
    public int remaining = Integer.MAX_VALUE;
    String key(Address a,String t,String c) { return a+":"+t+":"+c; }
    public Bookmark getBookmark(Address a,String t,String c) { return items.get(key(a,t,c)); }
    public Bookmark setBookmark(Address a,String t,String c,String text) {
        if (--remaining < 0) throw new IllegalStateException("write failure");
        Bookmark b=new Bookmark(text); items.put(key(a,t,c),b); return b;
    }
}
""",
    "ghidra/program/model/listing/Program.java": """
package ghidra.program.model.listing;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
public class Program {
    public Memory memory = new Memory();
    public Listing listing = new Listing();
    public BookmarkManager bookmarks = new BookmarkManager();
    public Address base = new Address(0x180000000L);
    public String sha;
    public boolean committed;
    java.util.Map<Address,String> oldComments;
    java.util.Map<String,Bookmark> oldBookmarks;
    public Memory getMemory() { return memory; }
    public Listing getListing() { return listing; }
    public BookmarkManager getBookmarkManager() { return bookmarks; }
    public Address getImageBase() { return base; }
    public String getExecutableSHA256() { return sha; }
    public int startTransaction(String title) {
        oldComments=new java.util.HashMap<>(listing.comments);
        oldBookmarks=new java.util.HashMap<>(bookmarks.items);
        committed=false;
        return 1;
    }
    public void endTransaction(int id,boolean commit) {
        committed=commit;
        if (!commit) { listing.comments=oldComments; bookmarks.items=oldBookmarks; }
    }
}
""",
}
