# Excel: synthetic workbook saved as password-protected .xls (BIFF8, xlExcel8 = 56)
$out = 'C:\fillyfoal\winfix\out\office\excel-rc4-cryptoapi.xls'
if (Test-Path $out) { Remove-Item $out }
$xl = New-Object -ComObject Excel.Application
$xl.Visible = $false
$xl.DisplayAlerts = $false
$xl.UserName = 'fillyfoal'
$wb = $xl.Workbooks.Add()
$ws = $wb.Worksheets.Item(1)
$ws.Name = 'fillyfoal test'
$ws.Cells.Item(1,1).Value2 = 'fillyfoal test'
$ws.Cells.Item(2,1).Value2 = 'item'; $ws.Cells.Item(2,2).Value2 = 'qty'; $ws.Cells.Item(2,3).Value2 = 'price'; $ws.Cells.Item(2,4).Value2 = 'total'
$rows = @(@('alpha',3,1.25),@('beta',7,2.5),@('gamma',11,0.75),@('delta',2,10))
for ($i=0; $i -lt $rows.Count; $i++) {
  $r = $i + 3
  $ws.Cells.Item($r,1).Value2 = $rows[$i][0]
  $ws.Cells.Item($r,2).Formula = [string]$rows[$i][1]
  $ws.Cells.Item($r,3).Formula = [string]$rows[$i][2]
  $ws.Cells.Item($r,4).Formula = "=B$r*C$r"
}
$ws.Cells.Item(7,1).Value2 = 'sum'
$ws.Cells.Item(7,4).Formula = '=SUM(D3:D6)'
# DocumentProperties is a late-bound Office collection: go through IDispatch explicitly
function Set-DocProp($doc, $name, $value) {
  $props = [System.__ComObject].InvokeMember('BuiltinDocumentProperties', 'GetProperty', $null, $doc, $null)
  $prop = [System.__ComObject].InvokeMember('Item', 'GetProperty', $null, $props, @($name))
  [void][System.__ComObject].InvokeMember('Value', 'SetProperty', $null, $prop, @($value))
}
foreach ($n in 'Author','Last author','Company') { Set-DocProp $wb $n 'fillyfoal' }
Set-DocProp $wb 'Title' 'fillyfoal test'
$wb.SaveAs($out, 56, 'fillyfoal')
$wb.Close($false)
try { $xl.Quit() } catch { Start-Sleep 3; try { $xl.Quit() } catch {} }   # Quit can transiently fail with 0x800AC472 (busy)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($xl)
"saved $out"


