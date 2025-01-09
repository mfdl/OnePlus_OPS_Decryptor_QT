#include <QCoreApplication>
#include <opsdecrypt.h>

#include <iostream>
#include <string>

void messageHandler(QtMsgType type, const QMessageLogContext& a, const QString& msg) {
    const QMap<QtMsgType, QString> typeStrings {
        { QtInfoMsg, "INFO" },
        { QtDebugMsg, "DBG" },
        { QtWarningMsg, "WARN" },
        { QtCriticalMsg, "CRIT" },
        { QtFatalMsg, "FATAL" },
    };
    OPSDecrypt::write_file("opsdecrypt.log", qbyte().append(msg).append("\n"), 1);
    std::cout << msg.toStdString().c_str() << std::endl;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qInstallMessageHandler(messageHandler);

    qInfo("........ OPLUS OPS file extractor .......");
    qInfo(".....................................................");

    if(argc < 2)
        qInfo("Drag and drop the .ops file");

    while (1) {

        QByteArray ops_path(0xff, Qt::Uninitialized);
        std::cin.get((char*)ops_path.data(), 0xff);

        qInfo(".....................................................");
        qInfo() << QString("Reading file %0").arg(ops_path.data());

        if(!qfileinfo(ops_path).size())
        {
            qInfo().noquote() << QString("invalid file !(%0)").arg(qt_error_string());
            ops_path.clear();
            return 0;
        }
        QSharedPointer<OPSDecrypt> ops(new OPSDecrypt());
        ops->UnpackOPS(ops_path);

        ops_path.clear();

        std::cin.ignore();
    }

    return(a.exec());
}
