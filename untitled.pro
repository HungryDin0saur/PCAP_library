#-------------------------------------------------
#
# Project created by QtCreator 2017-07-15T11:46:13
#
#-------------------------------------------------

INCLUDEPATH += "C:/WpdPack/Include"
INCLUDEPATH += "C:/WpdPack/Lib"

LIBS += -L"C:/WpdPack/Lib" -lwpcap -lpacket


DEFINES += WPCAP HAVE_REMOTE

QT       += core

QT       -= gui

TARGET = untitled
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp

