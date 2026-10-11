REM Saves a password-protected .xls (password "fillyfoal") with LibreOffice:
REM headless --convert-to ignores the Password property, so this runs as a
REM Basic macro in a throwaway profile (see encrypt.sh).
Sub Main
  Dim load(0) As New com.sun.star.beans.PropertyValue
  load(0).Name = "Hidden"
  load(0).Value = True
  doc = StarDesktop.loadComponentFromURL("private:factory/scalc", "_blank", 0, load())
  sheet = doc.Sheets.getByIndex(0)
  sheet.Name = "Secret"
  sheet.getCellByPosition(0, 0).String = "Hidden text"
  sheet.getCellByPosition(1, 0).Value = 42
  doc.DocumentProperties.Author = "fillyfoal"
  doc.DocumentProperties.ModifiedBy = "fillyfoal"
  Dim save(1) As New com.sun.star.beans.PropertyValue
  save(0).Name = "FilterName"
  save(0).Value = "MS Excel 97"
  save(1).Name = "Password"
  save(1).Value = "fillyfoal"
  doc.storeToURL(Environ("XLS_OUT"), save())
  doc.close(True)
  StarDesktop.terminate()
End Sub
