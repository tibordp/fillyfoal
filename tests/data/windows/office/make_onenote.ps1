# OneNote: local notebook (no account) with one section and one page, via the OneNote COM API.
$nbDir = 'C:\fillyfoal\winfix\work\office\notebook\fillyfoal-notebook'
New-Item -ItemType Directory -Force (Split-Path $nbDir) | Out-Null
$on = New-Object -ComObject OneNote.Application
$nbId = ''; $secId = ''; $pageId = ''
$on.OpenHierarchy($nbDir, '', [ref]$nbId, 1)          # cftNotebook = 1
"notebook id: $nbId"
$on.OpenHierarchy('fillyfoal-section.one', $nbId, [ref]$secId, 3)   # cftSection = 3
"section id: $secId"
$on.CreateNewPage($secId, [ref]$pageId, 0)
"page id: $pageId"
$ns = 'http://schemas.microsoft.com/office/onenote/2013/onenote'
$xml = @"
<?xml version="1.0"?>
<one:Page xmlns:one="$ns" ID="$pageId">
  <one:Title><one:OE><one:T><![CDATA[fillyfoal test]]></one:T></one:OE></one:Title>
  <one:Outline>
    <one:OEChildren>
      <one:OE><one:T><![CDATA[Lorem ipsum dolor sit amet.]]></one:T></one:OE>
      <one:OE><one:T><![CDATA[Synthetic content for a file-format test fixture.]]></one:T></one:OE>
      <one:OE><one:T><![CDATA[1, 2, 3]]></one:T></one:OE>
      <one:OE>
        <one:Table bordersVisible="true">
          <one:Columns><one:Column index="0" width="80"/><one:Column index="1" width="80"/></one:Columns>
          <one:Row>
            <one:Cell><one:OEChildren><one:OE><one:T><![CDATA[item]]></one:T></one:OE></one:OEChildren></one:Cell>
            <one:Cell><one:OEChildren><one:OE><one:T><![CDATA[qty]]></one:T></one:OE></one:OEChildren></one:Cell>
          </one:Row>
          <one:Row>
            <one:Cell><one:OEChildren><one:OE><one:T><![CDATA[alpha]]></one:T></one:OE></one:OEChildren></one:Cell>
            <one:Cell><one:OEChildren><one:OE><one:T><![CDATA[3]]></one:T></one:OE></one:OEChildren></one:Cell>
          </one:Row>
          <one:Row>
            <one:Cell><one:OEChildren><one:OE><one:T><![CDATA[beta]]></one:T></one:OE></one:OEChildren></one:Cell>
            <one:Cell><one:OEChildren><one:OE><one:T><![CDATA[7]]></one:T></one:OE></one:OEChildren></one:Cell>
          </one:Row>
        </one:Table>
      </one:OE>
    </one:OEChildren>
  </one:Outline>
</one:Page>
"@
$on.UpdatePageContent($xml, [DateTime]::MinValue, 2)   # xs2013
$check = ''
$on.GetPageContent($pageId, [ref]$check, 0, 2)
"page content has table: $($check.Contains('one:Table'))"
# OneNote writes to disk lazily; wait until the page text has reached the section file
$sec = Join-Path $nbDir 'fillyfoal-section.one'
for ($i = 0; $i -lt 60; $i++) {
  try { $on.SyncHierarchy($nbId) } catch {}
  Start-Sleep 5
  # ASCII-only text is stored as 8-bit (TextExtendedAscii), so search a Latin-1 view
  $u = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($sec))
  if ($u.Contains('Lorem ipsum')) { "flushed after $((($i+1)*5)) s"; break }
}
$on.CloseNotebook($nbId)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($on)
Get-ChildItem -Force $nbDir



