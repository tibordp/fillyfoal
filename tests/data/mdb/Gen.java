// Writes the external Access fixtures with Jackcess (see make.sh):
//
//   java -cp jackcess.jar:commons-lang3.jar:commons-logging.jar Gen.java OUTDIR
//
// One database per file format Jackcess can write (Jet 4 and ACE 14;
// it reads Jet 3 but does not write it) with the same table `Parts`: an autonumber
// key, every common column type, a memo short enough to stay in the row,
// one on its own long-value page and one chained over several pages, a
// deleted row and an index on Name.
import com.healthmarketscience.jackcess.*;
import java.io.File;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.*;

public class Gen {
    public static void main(String[] args) throws Exception {
        String out = args[0];
        make(new File(out, "jet4.mdb"), Database.FileFormat.V2000);
        make(new File(out, "ace.accdb"), Database.FileFormat.V2010);
    }

    static String repeat(String s, int n) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < n; i++) b.append(s);
        return b.toString();
    }

    static void make(File file, Database.FileFormat format) throws Exception {
        file.delete();
        try (Database db = new DatabaseBuilder(file).setFileFormat(format).create()) {
            TableBuilder tb = new TableBuilder("Parts")
                .addColumn(new ColumnBuilder("ID", DataType.LONG).setAutoNumber(true))
                .addColumn(new ColumnBuilder("Name", DataType.TEXT).setLengthInUnits(40))
                .addColumn(new ColumnBuilder("Qty", DataType.INT))
                .addColumn(new ColumnBuilder("InStock", DataType.BOOLEAN))
                .addColumn(new ColumnBuilder("Price", DataType.MONEY))
                .addColumn(new ColumnBuilder("Weight", DataType.DOUBLE))
                .addColumn(new ColumnBuilder("Ratio", DataType.FLOAT))
                .addColumn(new ColumnBuilder("Added", DataType.SHORT_DATE_TIME))
                .addColumn(new ColumnBuilder("Code", DataType.GUID))
                .addColumn(new ColumnBuilder("Level", DataType.BYTE))
                .addColumn(new ColumnBuilder("Tag", DataType.BINARY).setLength(8))
                .addColumn(new ColumnBuilder("Note", DataType.MEMO))
                .addColumn(new ColumnBuilder("Blob", DataType.OLE));
            tb.addColumn(new ColumnBuilder("Amount", DataType.NUMERIC)
                .setPrecision(18).setScale(4));
            tb.setPrimaryKey("ID");
            tb.addIndex(new IndexBuilder("ByName").addColumns("Name"));
            Table t = tb.toTable(db);
            String[] names = {"bolt", "nut", "washer", "gear", "spring", "axle", "pulley", "cam"};
            for (int i = 0; i < names.length; i++) {
                String note;
                if (i == 1) note = null;
                else if (i == 2) note = repeat("long note ", 300);          // own LVAL page
                else if (i == 3) note = repeat("chained memo text ", 700);  // several pages
                else note = "note " + names[i];
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("Name", names[i]);
                row.put("Qty", (short) (i * 7 - 3));
                row.put("InStock", i % 2 == 0);
                row.put("Price", new BigDecimal("12.3400").add(BigDecimal.valueOf(i)));
                row.put("Weight", 0.5 * i + 0.25);
                row.put("Ratio", (float) (i / 4.0));
                row.put("Added", LocalDateTime.of(2001, 2, 3 + i, 4, 5, 6));
                row.put("Code", String.format("{%08X-0000-4000-8000-%012X}", i + 1, 0xabcdefL * (i + 1)));
                row.put("Level", (byte) (i * 30));
                row.put("Tag", i == 5 ? null : new byte[] {1, 2, 3, (byte) i});
                row.put("Note", note);
                row.put("Blob", i == 4 ? new byte[] {(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef} : null);
                row.put("Amount", new BigDecimal("-1234.5678").multiply(BigDecimal.valueOf(i + 1)));
                t.addRowFromMap(row);
            }
            // Delete "pulley" so one row offset carries the deleted flag.
            for (Row r : t) {
                if ("pulley".equals(r.get("Name"))) {
                    t.deleteRow(r);
                    break;
                }
            }
        }
    }
}
