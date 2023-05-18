# Анализ запроса neo4j для пакета rome.1.9.0

## Пример работы
Рассмотрим запрос 
```
    match (source:Method) where source.NAME in ["equals","hashCode","compareTo"] 
    match (sink:Method {IS_SINK:true}) where sink.NAME =~ "invoke" and sink.VUL =~ "CODE" and sink.CLASSNAME =~ "java.lang.reflect.Method"
    call apoc.algo.allSimplePaths(sink,source, "<CALL|ALIAS", 10) yield path 
    where none(n in nodes(path) where (n.CLASSNAME =~ "java.util.Iterator" or n.CLASSNAME =~ "java.util.Enumeration" or n.CLASSNAME =~ "java.util.Map" or n.CLASSNAME =~ "java.util.List" or n.CLASSNAME=~"jdk.nashorn.internal.ir.UnaryNode" or n.CLASSNAME=~"com.sun.jndi.ldap.ClientId" or n.CLASSNAME=~"org.apache.catalina.webresources.TrackedInputStream"))
    return path limit 1

```

Так как во вермя анализа запроса я пришёл к выводу, что в уязвимость в данной цепочке вызвать не получится, то предлагаю сразу перейти к анализу проблемного места в классе `CloneableBean`:
+ Начинается всё с вызова метода clone:
```
com.rometools.rome.feed.impl.CloneableBean.clone()

    public Object clone() throws CloneNotSupportedException {
        return this.beanClone();
    }
```
+ Просто вызов следующего метода
```
com.rometools.rome.feed.impl.CloneableBean.beanClone()

    public Object beanClone() throws CloneNotSupportedException {
        Class<? extends Object> clazz = this.obj.getClass();

        try {
            Object clonedBean = clazz.newInstance();
            List<PropertyDescriptor> propertyDescriptors = BeanIntrospector.getPropertyDescriptorsWithGettersAndSetters(clazz);
            Iterator var4 = propertyDescriptors.iterator();

            while(var4.hasNext()) {
                PropertyDescriptor propertyDescriptor = (PropertyDescriptor)var4.next();
                String propertyName = propertyDescriptor.getName();
                boolean ignoredProperty = this.ignoreProperties.contains(propertyName);
                if (!ignoredProperty) {
                    Method getter = propertyDescriptor.getReadMethod();
                    Method setter = propertyDescriptor.getWriteMethod();
                    Object value = getter.invoke(this.obj, NO_PARAMS);
                    if (value != null) {
                        value = this.doClone(value);
                        setter.invoke(clonedBean, value);
                    }
                }
            }

            return clonedBean;
        } catch (CloneNotSupportedException var11) {
            LOG.error("Error while cloning bean", var11);
            throw var11;
        } catch (Exception var12) {
            LOG.error("Error while cloning bean", var12);
            throw new CloneNotSupportedException("Cannot clone a " + clazz + " object");
        }
    }

```
+ Следующим интересующим нас методом является метод *doClone*. Для того, чтобы вызвать этод метод нужно несколько условий. Для начала, объект, хранящийся в поле *obj* должен иметь некоторый геттер (и начинается он, соответсвенно, с get). Далее по этому геттеру достаётся проинициализированный объект, для которого уже и вызывается *doClone*.
```
com.rometools.rome.feed.impl.CloneableBean.doClone()

    private <T> T doClone(T value) throws Exception {
        if (value != null) {
            Class<?> vClass = value.getClass();
            if (vClass.isArray()) {
                value = this.cloneArray(value);
            } else if (value instanceof Collection) {
                value = this.cloneCollection((Collection)value);
            } else if (value instanceof Map) {
                value = this.cloneMap((Map)value);
            } else if (!this.isBasicType(vClass)) {
                if (!(value instanceof Cloneable)) {
                    throw new CloneNotSupportedException("Cannot clone a " + vClass.getName() + " object");
                }

                Method cloneMethod = vClass.getMethod("clone", NO_PARAMS_DEF);
                if (!Modifier.isPublic(cloneMethod.getModifiers())) {
                    throw new CloneNotSupportedException("Cannot clone a " + value.getClass() + " object, clone() is not public");
                }

                value = cloneMethod.invoke(value, NO_PARAMS);
            }
        }

        return value;
    }
```
+ Чтобы дойти до метода invoke, *value* должен иметь следующие ограничения: иметь публичный clone и наследоваться от clonable, а так же не быть массивом, map-ой, коллекцией и примитивным типом. Главное ограничение: invoke вызывает метод clone для *value*. Это очень сильно сужает выбор используемых классов, не говоря уже о том, что до этого invoke надо ещё добраться с соблюдением всех выше перечисленных условий.

### Ещё некоторые проблемы с запросом
Запрос начинается с сравнения двух экземпляров класса `EncryptedPrivateKeyInfo`. После этого как раз вызовется метод *clone* у хранимого внутри `CloneBean`, однако этот экземпляр хранится в виде массива байт, закодированного в ASN.1. Для этого кодирования нужно дополнительно описать алгоритм кодирования, но во время вызова *clone* вызова соответсвующего *clone* у `CloneBean` не последует.
