import sqlite3
import json
db_path = 'oui.db'  
json_path = 'manufacturers.json'  

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS manufacturers (
    mac_prefix TEXT,
    short_name TEXT,
    full_name TEXT
);
''')

with open(json_path, 'r') as file:
    data = json.load(file)

for item in data:
    cursor.execute('''
    INSERT INTO manufacturers (mac_prefix, short_name, full_name)
    VALUES (?, ?, ?)
    ''', (item['mac_prefix'], item['short_name'], item['full_name']))

conn.commit()
cursor.close()
conn.close()
