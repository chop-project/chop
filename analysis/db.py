import psycopg2

# TODO replace all pycopg2 calls with calls to db_connect so we don't
# have credentials all over the place
def db_connect():
   return psycopg2.connect(
         host="localhost",
         database="exceptionalresearch",
         user="ubuntu",
         password="exceptionalresearch",
   )
