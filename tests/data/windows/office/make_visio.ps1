# Visio: small drawing (3 shapes, 2 connectors, text) saved as Visio 2003-2010 binary .vsd
$out = 'C:\fillyfoal\winfix\out\office\visio-drawing.vsd'
if (Test-Path $out) { Remove-Item $out }
$vi = New-Object -ComObject Visio.InvisibleApp
$vi.AlertResponse = 7   # answer "No" to any prompt
$doc = $vi.Documents.Add('')
$page = $doc.Pages.Item(1)
$a = $page.DrawRectangle(1, 8, 3, 9);  $a.Text = 'fillyfoal test'
$b = $page.DrawOval(4, 8, 6, 9);       $b.Text = 'alpha'
$c = $page.DrawRectangle(4, 5, 6, 6);  $c.Text = 'beta'
$conn = $vi.ConnectorToolDataObject
$k1 = $page.Drop($conn, 0, 0); $k1.CellsU('BeginX').GlueTo($a.CellsU('PinX')); $k1.CellsU('EndX').GlueTo($b.CellsU('PinX'))
$k2 = $page.Drop($conn, 0, 0); $k2.CellsU('BeginX').GlueTo($b.CellsU('PinX')); $k2.CellsU('EndX').GlueTo($c.CellsU('PinX'))
$k2.Text = 'link'
$doc.Creator = 'fillyfoal'
$doc.Company = 'fillyfoal'
$doc.Title = 'fillyfoal test'
$doc.SaveAs($out)    # .vsd extension selects the Visio 2003-2010 Drawing format
$doc.Close()
$vi.Quit()
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($vi)
"saved $out"
