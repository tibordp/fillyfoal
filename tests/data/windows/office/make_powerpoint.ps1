# PowerPoint: two synthetic slides saved as password-protected .ppt (ppSaveAsPresentation = 1)
$out = 'C:\fillyfoal\winfix\out\office\powerpoint-encrypted.ppt'
if (Test-Path $out) { Remove-Item $out }
$pp = New-Object -ComObject PowerPoint.Application
$pres = $pp.Presentations.Add(0)   # msoFalse: no window
$s1 = $pres.Slides.Add(1, 1)       # ppLayoutTitle
$s1.Shapes.Item(1).TextFrame.TextRange.Text = 'fillyfoal test'
$s1.Shapes.Item(2).TextFrame.TextRange.Text = 'synthetic presentation'
$s2 = $pres.Slides.Add(2, 2)       # ppLayoutText
$s2.Shapes.Item(1).TextFrame.TextRange.Text = 'Lorem ipsum'
$s2.Shapes.Item(2).TextFrame.TextRange.Text = "dolor sit amet`rconsectetur adipiscing elit`r1, 2, 3"
function Set-DocProp($doc, $name, $value) {
  $props = [System.__ComObject].InvokeMember('BuiltInDocumentProperties', 'GetProperty', $null, $doc, $null)
  $prop = [System.__ComObject].InvokeMember('Item', 'GetProperty', $null, $props, @($name))
  [void][System.__ComObject].InvokeMember('Value', 'SetProperty', $null, $prop, @($value))
}
foreach ($n in 'Author','Last author','Company') { Set-DocProp $pres $n 'fillyfoal' }
Set-DocProp $pres 'Title' 'fillyfoal test'
$pres.Password = 'fillyfoal'
$pres.SaveAs($out, 1)
$pres.Close()
$pp.Quit()
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($pp)
"saved $out"

