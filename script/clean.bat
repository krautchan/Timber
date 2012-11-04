@echo off

cd ..

attrib -h -s log.txt
attrib -h timber.suo
del /q log.txt
del /q remotelog.txt
del /q memlog.txt
del /q timber.suo
del /q timber.sdf
del /q timber.opensdf
del /q include\server_key.h
del /q include\client_key.h
rd /q /s debug
rd /q /s release
rd /q /s ipch

rd /q /s keygen\debug
rd /q /s keygen\release
del /q keygen\keygen.vcxproj.user
del /q keygen\keygen.sdf

rd /q /s client\debug
rd /q /s client\release
del /q client\client.vcxproj.user
del /q client\client.sdf

rd /q /s server\debug
rd /q /s server\release
del /q server\server.vcxproj.user
del /q server\server.sdf

cd script