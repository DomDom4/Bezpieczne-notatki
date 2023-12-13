from sqlite3 import connect

db_name = 'users.db'

con = connect(db_name)
c = con.cursor()

c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT
            );
          ''')

c.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                username TEXT,
                content TEXT,
                is_shared INTEGER,
                FOREIGN KEY (username) REFERENCES users(username)
            )
          ''')

con.commit()
con.close()
