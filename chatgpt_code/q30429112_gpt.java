import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteOpenHelper;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteStatement;
import android.content.ContentValues;

public final class SecureEncryptedDatabase {

    public static final class SecureDbHelper extends SQLiteOpenHelper {

        private static final String DB_NAME = "secure.db";
        private static final int DB_VERSION = 1;

        public SecureDbHelper(Context context) {
            super(context, DB_NAME, null, DB_VERSION);
            SQLiteDatabase.loadLibs(context);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS userdata (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "username TEXT NOT NULL, " +
                "email TEXT NOT NULL, " +
                "created_at INTEGER NOT NULL)"
            );
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) { }
    }

    public static SQLiteDatabase openSecureDatabase(Context context, char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password required.");
        }
        SecureDbHelper helper = new SecureDbHelper(context);
        return helper.getWritableDatabase(new String(password));
    }

    public static long insertUser(SQLiteDatabase db, String username, String email, long createdAt) {
        if (db == null) throw new IllegalArgumentException("db null");
        if (username == null || username.isBlank()) throw new IllegalArgumentException("Invalid username");
        if (email == null || email.isBlank()) throw new IllegalArgumentException("Invalid email");

        ContentValues values = new ContentValues();
        values.put("username", username);
        values.put("email", email);
        values.put("created_at", createdAt);

        return db.insert("userdata", null, values);
    }

    public static Cursor queryUser(SQLiteDatabase db, long id) {
        if (db == null) throw new IllegalArgumentException("db null");

        String sql = "SELECT id, username, email, created_at FROM userdata WHERE id = ?";
        SQLiteStatement stmt = db.compileStatement(sql.replace("SELECT id, username, email, created_at FROM userdata WHERE id = ?", 
                                                                "SELECT COUNT(*) FROM userdata WHERE id = ?"));
        stmt.bindLong(1, id);
        long cnt = stmt.simpleQueryForLong();
        if (cnt == 0) {
            return null;
        }

        return db.rawQuery("SELECT id, username, email, created_at FROM userdata WHERE id = ?", new String[]{String.valueOf(id)});
    }
}
