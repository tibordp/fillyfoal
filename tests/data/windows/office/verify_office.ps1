# Re-open every output in its producing application to verify it (read-only)
$o = 'C:\fillyfoal\winfix\out\office'
$xl = New-Object -ComObject Excel.Application; $xl.DisplayAlerts = $false
$wb = $xl.Workbooks.Open("$o\excel-rc4-cryptoapi.xls", 0, $true, [Type]::Missing, 'fillyfoal')
"xls: A1=$($wb.Worksheets.Item(1).Range('A1').Text) D7=$($wb.Worksheets.Item(1).Range('D7').Text) FileFormat=$($wb.FileFormat) HasPassword=$($wb.HasPassword) ProviderType=$($wb.PasswordEncryptionProvider) Algo=$($wb.PasswordEncryptionAlgorithm) KeyLen=$($wb.PasswordEncryptionKeyLength)"
$wb.Close($false); try { $xl.Quit() } catch { Start-Sleep 3; try { $xl.Quit() } catch {} }
$pp = New-Object -ComObject PowerPoint.Application
$pr = $pp.Presentations.Open("$o\powerpoint-encrypted.ppt::fillyfoal::", -1, 0, 0)
"ppt: slides=$($pr.Slides.Count) title=$($pr.Slides.Item(1).Shapes.Item(1).TextFrame.TextRange.Text) HasPassword=$($pr.HasPassword) Provider=$($pr.PasswordEncryptionProvider) Algo=$($pr.PasswordEncryptionAlgorithm) KeyLen=$($pr.PasswordEncryptionKeyLength)"
$pr.Close(); $pp.Quit()
$vi = New-Object -ComObject Visio.InvisibleApp
$d = $vi.Documents.OpenEx("$o\visio-drawing.vsd", 2)   # visOpenRO
"vsd: shapes=$($d.Pages.Item(1).Shapes.Count) version=$($d.Version) creator=$($d.Creator)"
$d.Close(); $vi.Quit()
