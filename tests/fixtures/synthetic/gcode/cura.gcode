;FLAVOR:Marlin
;TIME:754
;Filament used: 0.412m
;Layer height: 0.2
;MINX:100.2
;MINY:100.2
;MINZ:0.2
;MAXX:119.8
;MAXY:119.8
;MAXZ:0.6
;TARGET_MACHINE.NAME:Creality Ender-3
;Generated with Cura_SteamEngine 5.4.0
;
; thumbnail begin 16x16 136
; iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAALElEQVR4nGP88OEDAymAiSTVDPTQwI
; LM4apwxKroW8d+OjqJaSRqYBwGaQkAdisIwadpjn0AAAAASUVORK5CYII=
; thumbnail end
;
M140 S60
M105
M190 S60
M104 S200
M105
M109 S200
M82 ;absolute extrusion mode
G28 ;Home
G92 E0 ;Reset Extruder
G1 Z2.0 F3000 ;Move Z Axis up
G1 X0.1 Y20 Z0.3 F5000.0 ;Move to start position
G1 X0.1 Y200.0 Z0.3 F1500.0 E15 ;Draw the first line
G92 E0
G1 F2700 E-5
;LAYER_COUNT:3
;LAYER:0
M107
G0 F6000 X100.2 Y100.2 Z0.2
;TYPE:WALL-OUTER
G1 F2700 E0
G1 F1200 X119.8 Y100.2 E0.65172
G1 X119.8 Y119.8 E1.30344
G1 X100.2 Y119.8 E1.95516
G1 X100.2 Y100.2 E2.60688
;MESH:cube.stl
;TIME_ELAPSED:250.3
;LAYER:1
M106 S85
G0 F6000 X100.2 Y100.2 Z0.4
G1 F1200 X119.8 Y100.2 E3.2586
G1 X119.8 Y119.8 E3.91032
G1 X100.2 Y119.8 E4.56204
G1 X100.2 Y100.2 E5.21376
;TIME_ELAPSED:501.1
;LAYER:2
G0 F6000 X100.2 Y100.2 Z0.6
G1 F1200 X119.8 Y100.2 E5.86548
G1 X119.8 Y119.8 E6.5172
G1 X100.2 Y119.8 E7.16892
G1 X100.2 Y100.2 E7.82064
;TIME_ELAPSED:754.0
G1 F2700 E2.82064
M140 S0
M107
G91 ;Relative positioning
G1 E-2 F2700 ;Retract a bit
G90 ;Absolute positioning
M84 X Y E ;Disable all steppers but Z
M82 ;absolute extrusion mode
M104 S0
;End of Gcode
;SETTING_3 {"global_quality": "[general]\\nversion = 4\\nname = Standard Q
;SETTING_3 uality #2\\ndefinition = creality_ender3\\n\\n[metadata]\\ntype = qual
;SETTING_3 ity_changes\\nquality_type = standard\\n\\n[values]\\n\\n"}
