REM Saves a small password-protected document (password "fillyfoal") with
REM LibreOffice: headless --convert-to ignores the Password property, so this
REM runs as a Basic macro in a throwaway profile (see encrypt.sh). The
REM environment names the application (FACTORY: swriter or simpress), the
REM export filter (FILTER) and the output URL (OUT).
Sub Main
  Dim load(0) As New com.sun.star.beans.PropertyValue
  load(0).Name = "Hidden"
  load(0).Value = True
  factory = Environ("FACTORY")
  doc = StarDesktop.loadComponentFromURL("private:factory/" & factory, "_blank", 0, load())
  If factory = "swriter" Then
    doc.Text.setString("Hidden text")
  Else
    page = doc.DrawPages.getByIndex(0)
    shape = doc.createInstance("com.sun.star.drawing.TextShape")
    Dim size As New com.sun.star.awt.Size
    size.Width = 8000
    size.Height = 2000
    shape.setSize(size)
    page.add(shape)
    shape.setString("Hidden text")
  End If
  doc.DocumentProperties.Author = "fillyfoal"
  doc.DocumentProperties.ModifiedBy = "fillyfoal"
  Dim save(1) As New com.sun.star.beans.PropertyValue
  save(0).Name = "FilterName"
  save(0).Value = Environ("FILTER")
  save(1).Name = "Password"
  save(1).Value = "fillyfoal"
  doc.storeToURL(Environ("OUT"), save())
  doc.close(True)
  StarDesktop.terminate()
End Sub
