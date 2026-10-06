$ LS-DYNA keyword deck for testing
*KEYWORD
*TITLE
Impact test
*NODE
$#   nid               x               y               z
       1             0.0             0.0             0.0
       2             1.0             0.0             0.0
*PART
$#                                                                         title
block
$#     pid     secid       mid
         1         1         1
*MAT_ELASTIC
         1      7.85     210.0       0.3
*END
