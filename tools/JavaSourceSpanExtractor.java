import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;
import javax.tools.*;
import com.sun.source.tree.*;
import com.sun.source.util.*;

/** Parse only. Never calls analyze(), generate(), task.call(), or target code. */
public final class JavaSourceSpanExtractor {
    static String quote(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch(c) {
            case '"': b.append("\\\""); break; case '\\': b.append("\\\\"); break;
            case '\n': b.append("\\n"); break; case '\r': b.append("\\r"); break;
            case '\t': b.append("\\t"); break;
            default: if(c < 32 || Character.isSurrogate(c)) b.append(String.format("\\u%04x", (int)c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }
    static String json(Object o) {
        if(o == null || o instanceof String) return quote((String)o);
        if(o instanceof Number || o instanceof Boolean) return o.toString();
        if(o instanceof Map) {
            List<String> parts = new ArrayList<>();
            ((Map<?,?>)o).forEach((k,v)->parts.add(quote(k.toString())+":"+json(v)));
            return "{"+String.join(",",parts)+"}";
        }
        List<String> parts = new ArrayList<>();
        for(Object v : (Iterable<?>)o) parts.add(json(v));
        return "["+String.join(",",parts)+"]";
    }
    static Map<String,Object> obj(Object... kv) {
        Map<String,Object> out = new LinkedHashMap<>();
        for(int i=0;i<kv.length;i+=2)out.put((String)kv[i],kv[i+1]); return out;
    }
    static String digest(byte[] bytes) throws Exception {
        StringBuilder s = new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))s.append(String.format("%02x", b & 255));
        return s.toString();
    }
    static String leadingTrivia(String src,long start) {
        if(start<0 || start>src.length())return "";
        int end=(int)start, at=end;
        while(true) {
            while(at>0 && Character.isWhitespace(src.charAt(at-1)))at--;
            if(at>=2 && src.substring(at-2,at).equals("*/")) {
                int begin=src.lastIndexOf("/*",at-2);
                if(begin<0)break; at=begin;
            } else break;
        }
        return src.substring(at,end);
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("source-root fresh-output-jsonl");
        Path root=Paths.get(args[0]).toAbsolutePath().normalize(), output=Paths.get(args[1]);
        JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();
        if(compiler==null)throw new IllegalStateException("Full JDK required");
        List<Path> paths=new ArrayList<>();
        try(java.util.stream.Stream<Path> walk=Files.walk(root)){walk.filter(p->p.toString().endsWith(".java")).sorted().forEach(paths::add);}
        try(BufferedWriter writer=Files.newBufferedWriter(output,StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)) {
            for(Path path:paths) {
                byte[] raw=Files.readAllBytes(path); String src=new String(raw,StandardCharsets.UTF_8);
                List<Object> classes=new ArrayList<>(), methods=new ArrayList<>(), diagnostics=new ArrayList<>(), initializers=new ArrayList<>();
                DiagnosticCollector<JavaFileObject> collector=new DiagnosticCollector<>();
                String[] pkg={""}; List<Object> imports=new ArrayList<>();
                String failure=null;
                try(StandardJavaFileManager fm=compiler.getStandardFileManager(collector,Locale.ROOT,StandardCharsets.UTF_8)) {
                    JavacTask task=(JavacTask)compiler.getTask(null,fm,collector,Arrays.asList("-proc:none","-encoding","UTF-8"),null,fm.getJavaFileObjects(path.toFile()));
                    for(CompilationUnitTree cu:task.parse()) {
                        pkg[0]=cu.getPackageName()==null?"":cu.getPackageName().toString();
                        for(ImportTree im:cu.getImports())imports.add(obj("name",im.getQualifiedIdentifier().toString(),"static",im.isStatic()));
                        SourcePositions pos=Trees.instance(task).getSourcePositions();
                        new TreeScanner<Void,Void>() {
                            List<String> owners=new ArrayList<>();
                            List<String> typeVars=new ArrayList<>();
                            int methodDepth=0, initializerDepth=0;
                            long start(Tree t){return pos.getStartPosition(cu,t);}
                            long end(Tree t){return pos.getEndPosition(cu,t);}
                            String owner(){return String.join("$",owners);}
                            public Void visitClass(ClassTree c,Void v) {
                                String parent=owner(); owners.add(c.getSimpleName().toString());
                                int old=typeVars.size(); for(TypeParameterTree t:c.getTypeParameters())typeVars.add(t.getName().toString());
                                classes.add(obj("owner",owner(),"parent_owner",parent,"name",c.getSimpleName().toString(),"kind",c.getKind().toString(),"start",start(c),"end",end(c),"leading_trivia",leadingTrivia(src,start(c)),"local_or_anonymous",methodDepth>0||initializerDepth>0||c.getSimpleName().length()==0));
                                super.visitClass(c,v); while(typeVars.size()>old)typeVars.remove(typeVars.size()-1); owners.remove(owners.size()-1);return null;
                            }
                            public Void visitMethod(MethodTree m,Void v) {
                                List<Object> params=new ArrayList<>();
                                for(VariableTree p:m.getParameters()) {
                                    long a=start(p),b=end(p); String decl=a>=0&&b>=a?src.substring((int)a,(int)b):"";
                                    params.add(obj("type",p.getType()==null?null:p.getType().toString(),"declaration",decl,"varargs",decl.contains("...")));
                                }
                                List<String> vars=new ArrayList<>(typeVars);for(TypeParameterTree t:m.getTypeParameters())vars.add(t.getName().toString());
                                BlockTree body=m.getBody();
                                methods.add(obj("owner",owner(),"name",m.getName().toString(),"constructor",m.getReturnType()==null,"return_type",m.getReturnType()==null?"void":m.getReturnType().toString(),"parameters",params,"type_variables",vars,"start",start(m),"end",end(m),"body_start",body==null?null:start(body),"body_end",body==null?null:end(body),"leading_trivia",leadingTrivia(src,start(m)),"local_context",methodDepth>0||initializerDepth>0,"flags",m.getModifiers().getFlags().toString()));
                                methodDepth++;super.visitMethod(m,v);methodDepth--;return null;
                            }
                            public Void visitVariable(VariableTree x,Void v) {
                                if(methodDepth==0 && x.getInitializer()!=null) {
                                    initializerDepth++;super.visitVariable(x,v);initializerDepth--;return null;
                                }
                                return super.visitVariable(x,v);
                            }
                            public Void visitBlock(BlockTree b,Void v) {
                                if(methodDepth==0) {
                                    initializers.add(obj("owner",owner(),"static",b.isStatic(),"start",start(b),"end",end(b)));
                                    initializerDepth++;super.visitBlock(b,v);initializerDepth--;return null;
                                }
                                return super.visitBlock(b,v);
                            }
                        }.scan(cu,null);
                    }
                } catch(Exception ex) {failure=ex.getClass().getName()+": "+ex.getMessage();}
                boolean errors=failure!=null;
                for(Diagnostic<? extends JavaFileObject> d:collector.getDiagnostics()) {
                    if(d.getKind()==Diagnostic.Kind.ERROR)errors=true;
                    diagnostics.add(obj("kind",d.getKind().toString(),"code",d.getCode(),"start",d.getStartPosition(),"end",d.getEndPosition(),"line",d.getLineNumber(),"column",d.getColumnNumber(),"message",d.getMessage(Locale.ROOT)));
                }
                writer.write(json(obj("schema",1,"path",root.relativize(path).toString().replace('\\','/'),"sha256",digest(raw),"bytes",raw.length,"utf16_length",src.length(),"offset_unit","UTF-16 code units; half-open","package",pkg[0],"imports",imports,"classes",classes,"methods",methods,"initializers",initializers,"parse_errors",errors,"failure",failure,"diagnostics",diagnostics,"parse_only",true)));
                writer.newLine();writer.flush();
            }
        }
    }
}
