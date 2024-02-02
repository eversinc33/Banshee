@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc loaddriver.c
move /y loaddriver.obj loaddriver.o

