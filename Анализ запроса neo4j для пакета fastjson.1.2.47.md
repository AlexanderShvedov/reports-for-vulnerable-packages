# Анализ запроса neo4j для пакета fastjson.1.2.47

## Пример работы
Рассмотрим запрос 
```
    match path=(m1:Method)-[:CALL*..5]->(m2:Method {IS_SINK:true,NAME:"lookup"}) where m1.NAME =~ "set.*" return path
```

У меня не получилось полностью проверить выполнение этой цепочки, поэтому опишу сами методы и что ожидается от выполнения последнего из них.
+ Начинается всё с вызова метода setAutoCommit:
```
com.sun.rowset.JdbcRowSetImpl.setAutoCommit()

    public void setAutoCommit(boolean autoCommit) throws SQLException {
        // The connection object should be there
        // in order to commit the connection handle on or off.

        if(conn != null) {
           conn.setAutoCommit(autoCommit);
        } else {
           // Coming here means the connection object is null.
           // So generate a connection handle internally, since
           // a JdbcRowSet is always connected to a db, it is fine
           // to get a handle to the connection.

           // Get hold of a connection handle
           // and change the autcommit as passesd.
           conn = connect();

           // After setting the below the conn.getAutoCommit()
           // should return the same value.
           conn.setAutoCommit(autoCommit);

        }
    }
```
+ Нас интересует вызов метода *connect*. Для его вызова нам нужно только то, что мы ещё не коннектились к какому либо серверу.
```
com.sun.rowset.JdbcRowSetImpl.connect()

    private Connection connect() throws SQLException {

        // Get a JDBC connection.

        // First check for Connection handle object as such if
        // "this" initialized  using conn.

        if(conn != null) {
            return conn;

        } else if (getDataSourceName() != null) {

            // Connect using JNDI.
            try {
                Context ctx = new InitialContext();
                DataSource ds = (DataSource)ctx.lookup
                    (getDataSourceName());
                //return ds.getConnection(getUsername(),getPassword());

                if(getUsername() != null && !getUsername().equals("")) {
                     return ds.getConnection(getUsername(),getPassword());
                } else {
                     return ds.getConnection();
                }
            }
            catch (javax.naming.NamingException ex) {
                throw new SQLException(resBundle.handleGetObject("jdbcrowsetimpl.connect").toString());
            }

        } else if (getUrl() != null) {
            // Check only for getUrl() != null because
            // user, passwd can be null
            // Connect using the driver manager.

            return DriverManager.getConnection
                    (getUrl(), getUsername(), getPassword());
        }
        else {
            return null;
        }

```
+ Далее происходит основная работа. Опять же проверяется наличие коннекта, и если его нет, то проверяется, что у нас хранится адресс, куда нужно коннектится. Далее будет вызван метод *lookup* класса `InitialContext`. Это и есть уязвимый метод

### Что должно быть в теории, но не получилось добиться на практике
Перед тем, как пользователь позовёт опасный метод, где-то должен быть запущен сервер jndi/rmi (на любом устройстве, не обязательно на машине жертвы), на котором лежит файл с расширением .class с необходимым нам произвольным кодом. Далее пользователь в *dataSource* назначает путь до нашего опасного файла и вызывает setAutoCommit (это может произойти, если с помощью fastjson пользователь распарсит переданную нами опасную строчку json-а). Далее в методе *loockup* пользователь приконнектится к нашему файлу и вызовет имеющийся в нём метод.

Из выше перечисленного у меня получилось создать сервер, пользователь к нему коннектится, но не находит необходимый файл/метод.