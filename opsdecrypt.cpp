#include "opsdecrypt.h"

OPSDecrypt::OPSDecrypt()
{
    qInfo().nospace() << "ctor of " << (this);
}

qbool OPSDecrypt::UnpackXML(OPSDeviceInfo &oinfo)
{
    oinfo.m_xml_dev.clear();

    qlong ops_len{qlong(oinfo.m_ops_dev->size())};
    if (!oinfo.m_ops_dev->seek(ops_len - oinfo.m_blksz))
        return 0;

    qbyte ops_hdr{oinfo.m_ops_dev->read(oinfo.m_blksz)};
    quint xml_len{(*(quint_le*)(ops_hdr.mid(0x18, 4).data()))};
    quint xml_pad{(oinfo.m_blksz - (xml_len % oinfo.m_blksz))};
    if (!oinfo.m_ops_dev->seek(ops_len - oinfo.m_blksz - (xml_len + xml_pad)))
        return 0;

    oinfo.m_tmp_buff = {oinfo.m_ops_dev->read(xml_len + xml_pad)};
    if (!DecOpsData(oinfo))
        return(0);

    oinfo.m_xml_dev = {oinfo.m_tmp_buff.mid(0, xml_len)};
    if (!oinfo.m_xml_dev.contains("xml"))
        return(0);

    if (!write_file(qstr("%0/settings.xml").arg(oinfo.m_out_path), oinfo.m_xml_dev, 0))
        return(0);

    return oinfo.m_xml_dev.size();
}

qbool OPSDecrypt::GetOPSEntries(OPSDeviceInfo &oinfo)
{
    QDomDocument doc{};
    if (!doc.setContent(oinfo.m_xml_dev))
        return(0);

    qsizetype idx{0};
    QDomElement element = doc.documentElement().firstChildElement();
    while (!element.isNull())
    {
        if (element.tagName() == QByteArrayLiteral("BasicInfo"))
        {
            QDomNamedNodeMap attrs{element.attributes()};
            oinfo.m_ops_dl_info.insert("Project", (attrs.namedItem("Project").toAttr().value()));
            oinfo.m_ops_dl_info.insert("TargetName", (attrs.namedItem("TargetName").toAttr().value()));
            oinfo.m_ops_dl_info.insert("Version", (attrs.namedItem("Version").toAttr().value()));
            oinfo.m_ops_dl_info.insert("MemoryName", (attrs.namedItem("MemoryName").toAttr().value()));
            oinfo.m_ops_dl_info.insert("GrowLastPartToFillDisk", (attrs.namedItem("GrowLastPartToFillDisk").toAttr().value()));
            oinfo.m_ops_dl_info.insert("LogEnable", (attrs.namedItem("LogEnable").toAttr().value()));
            oinfo.m_ops_dl_info.insert("LogPositionIndex", (attrs.namedItem("LogPositionIndex").toAttr().value()));
            oinfo.m_ops_dl_info.insert("DelayStartTime", (attrs.namedItem("DelayStartTime").toAttr().value()));
            oinfo.m_ops_dl_info.insert("UseGPT", (attrs.namedItem("UseGPT").toAttr().value()));
            oinfo.m_ops_dl_info.insert("CheckImage", (attrs.namedItem("CheckImage").toAttr().value()));
            oinfo.m_ops_dl_info.insert("CheckHwVersion", (attrs.namedItem("CheckHwVersion").toAttr().value()));
            oinfo.m_ops_dl_info.insert("NeedUsbDownload", (attrs.namedItem("NeedUsbDownload").toAttr().value()));
            oinfo.m_ops_dl_info.insert("BackupPart", (attrs.namedItem("BackupPart").toAttr().value()));
            oinfo.m_ops_dl_info.insert("BackupPartId", (attrs.namedItem("BackupPartId").toAttr().value()));
            oinfo.m_ops_dl_info.insert("ChipType", (attrs.namedItem("ChipType").toAttr().value()));
            oinfo.m_ops_dl_info.insert("FactoryID", (attrs.namedItem("FactoryID").toAttr().value()));
            oinfo.m_ops_dl_info.insert("MinToolVersion", (attrs.namedItem("MinToolVersion").toAttr().value()));
            oinfo.m_ops_dl_info.insert("SupportHwID", (attrs.namedItem("SupportHwID").toAttr().value()));
            oinfo.m_ops_dl_info.insert("SupportRfID", (attrs.namedItem("SupportRfID").toAttr().value()));
            oinfo.m_ops_dl_info.insert("SupportPrjID", (attrs.namedItem("SupportPrjID").toAttr().value()));
            oinfo.m_ops_dl_info.insert("CheckRfVersion", (attrs.namedItem("CheckRfVersion").toAttr().value()));
            oinfo.m_ops_dl_info.insert("CheckProjectVersion", (attrs.namedItem("CheckProjectVersion").toAttr().value()));
            oinfo.m_ops_dl_info.insert("SkipImgSHA256Check", (attrs.namedItem("SkipImgSHA256Check").toAttr().value()));
            oinfo.m_ops_dl_info.insert("ParamVersion", (attrs.namedItem("ParamVersion").toAttr().value()));
            oinfo.m_ops_dl_info.insert("SkipParamProcess", (attrs.namedItem("SkipParamProcess").toAttr().value()));
            oinfo.m_ops_dl_info.insert("ModelVerifyVersion", (attrs.namedItem("ModelVerifyVersion").toAttr().value()));
            oinfo.m_ops_dl_info.insert("ModelVerifyPrjName", (attrs.namedItem("ModelVerifyPrjName").toAttr().value()));
            oinfo.m_ops_dl_info.insert("SkipCheckHWVerByCustFlag", (attrs.namedItem("SkipCheckHWVerByCustFlag").toAttr().value()));
            oinfo.m_ops_dl_info.insert("DefaultCleanFRP", (attrs.namedItem("DefaultCleanFRP").toAttr().value()));
            oinfo.m_ops_dl_info.insert("FrpPartitionLabel", (attrs.namedItem("FrpPartitionLabel").toAttr().value()));
            oinfo.m_ops_dl_info.insert("CarrierID", (attrs.namedItem("CarrierID").toAttr().value()));
            oinfo.m_ops_dl_info.insert("SendIntranetFlag", (attrs.namedItem("SendIntranetFlag").toAttr().value()));
            oinfo.m_ops_dl_info.insert("AutoDetectDDR", (attrs.namedItem("AutoDetectDDR").toAttr().value()));
            oinfo.m_ops_dl_info.insert("DPPackingVer", (attrs.namedItem("DPPackingVer").toAttr().value()));
            oinfo.m_ops_dl_info.insert("RandomPadding", (attrs.namedItem("RandomPadding").toAttr().value()));
            oinfo.m_ops_dl_info.insert("ModelVerifyRandom", (attrs.namedItem("ModelVerifyRandom").toAttr().value()));
            oinfo.m_ops_dl_info.insert("ModelVerifyHashToken", (attrs.namedItem("ModelVerifyHashToken").toAttr().value()));
            oinfo.m_ops_dl_info.insert("Applicant", (attrs.namedItem("Applicant").toAttr().value()));
            oinfo.m_ops_dl_info.insert("Hostname", (attrs.namedItem("Hostname").toAttr().value()));
            oinfo.m_ops_dl_info.insert("BuildTime", (attrs.namedItem("BuildTime").toAttr().value()));
            oinfo.m_ops_dl_info.insert("ApplicantIP", (attrs.namedItem("ApplicantIP").toAttr().value()));
        }
        else if (element.tagName() == QByteArrayLiteral("SAHARA"))
        {
            QDomNodeList root{element.childNodes()};
            for (qint i{0}; i < root.size(); i++)
            {
                OPSEntry fh_prog = {};
                QDomNamedNodeMap attrs{root.item(i).attributes()};
                fh_prog.m_pname = (attrs.namedItem("Path").toAttr().value());
                fh_prog.m_fname = (attrs.namedItem("Path").toAttr().value());
                fh_prog.m_offset = (attrs.namedItem("FileOffsetInSrc").toAttr().value().toULongLong() * oinfo.m_blksz);
                fh_prog.m_length = (attrs.namedItem("SizeInSectorInSrc").toAttr().value().toULongLong() * oinfo.m_blksz);
                fh_prog.m_tmplen = (attrs.namedItem("SizeInByteInSrc").toAttr().value().toULongLong());
                if ((!fh_prog.m_fname.size() ||
                     fh_prog.m_length == 0 ||
                     fh_prog.m_tmplen == 0))
                    continue;

                fh_prog.m_index = {idx};
                fh_prog.m_decode = {1};
                oinfo.m_entries.push_back(fh_prog);
                idx++;
            }
        }
        else if (element.tagName() == QByteArrayLiteral("UFS_PROVISION"))
        {
            QDomNodeList root{element.childNodes()};
            for (qint i{0}; i < root.size(); i++)
            {
                OPSEntry ufs_prov = {};
                QDomNamedNodeMap attrs{root.item(i).attributes()};
                ufs_prov.m_pname = (attrs.namedItem("Path").toAttr().value());
                ufs_prov.m_fname = (attrs.namedItem("Path").toAttr().value());
                ufs_prov.m_offset = (attrs.namedItem("FileOffsetInSrc").toAttr().value().toULongLong() * oinfo.m_blksz);
                ufs_prov.m_length = (attrs.namedItem("SizeInSectorInSrc").toAttr().value().toULongLong() * oinfo.m_blksz);
                ufs_prov.m_tmplen = (attrs.namedItem("SizeInByteInSrc").toAttr().value().toULongLong());
                if ((!ufs_prov.m_fname.size() ||
                     ufs_prov.m_length == 0 ||
                     ufs_prov.m_tmplen == 0))
                    continue;

                ufs_prov.m_index = {idx};
                ufs_prov.m_decode = {0};
                oinfo.m_entries.push_back(ufs_prov);
                idx++;
            }
        }
        else if (element.tagName().startsWith(QByteArrayLiteral("Program")))
        {
            QDomNodeList root{element.elementsByTagName("Image")};
            if (!root.size())
                root = {element.childNodes()};
            for (qint i{0}; i < root.size(); i++)
            {
                OPSEntry ops_part = {};
                QDomNamedNodeMap attrs{root.item(i).attributes()};
                ops_part.m_lunid = {element.tagName().replace("Program", "").toInt()};
                ops_part.m_pname = (attrs.namedItem("filename").toAttr().value());
                ops_part.m_fname = (attrs.namedItem("filename").toAttr().value());
                ops_part.m_sparse = (attrs.namedItem("sparse").toAttr().value().toInt());
                ops_part.m_offset = (attrs.namedItem("FileOffsetInSrc").toAttr().value().toULongLong() * oinfo.m_blksz);
                ops_part.m_length = (attrs.namedItem("SizeInSectorInSrc").toAttr().value().toULongLong() * oinfo.m_blksz);
                ops_part.m_tmplen = (attrs.namedItem("SizeInByteInSrc").toAttr().value().toULongLong());
                if ((!ops_part.m_fname.size() ||
                     ops_part.m_length == 0 ||
                     ops_part.m_tmplen == 0))
                    continue;

                ops_part.m_decode = {0};
                ops_part.m_index = {idx};
                oinfo.m_entries.push_back(ops_part);
                idx++;
            }
        }
        element = {element.nextSiblingElement()};
    }

    doc.clear();
    element.clear();
    return {qbool(oinfo.m_entries.size())};
}

qbool OPSDecrypt::OPSGetKey(OPSDeviceInfo &oinfo)
{
    std::function<quint(qsizetype)> ops_gsbox = [&]
            (qsizetype offset)
    {
        qbyte sbox{(qbyte::fromHex(OPSSBOX))};
        return (*(quint_le*)(sbox.mid(offset, 4).data()));
    };

    quint d{oinfo.m_ops_key.key_pair[0] ^ oinfo.m_ops_key.ops_ievc[0]};  //# 9EE3B5B1
    quint a{oinfo.m_ops_key.key_pair[1] ^ oinfo.m_ops_key.ops_ievc[1]};
    quint b{oinfo.m_ops_key.key_pair[2] ^ oinfo.m_ops_key.ops_ievc[2]};  //# ABD51D58
    quint c{oinfo.m_ops_key.key_pair[3] ^ oinfo.m_ops_key.ops_ievc[3]};  //# AFCBAFFF

    quint e =  {
        ops_gsbox(((b >> 0x10) & 0xff) * 8 + 2) ^
        ops_gsbox(((a >> 8) & 0xff) * 8 + 3) ^
        ops_gsbox((c >> 0x18) * 8 + 1) ^
        ops_gsbox((d & 0xff) * 8) ^ \
        oinfo.m_ops_key.ops_ievc[4]
    };  //# 35C2A10B
    quint h = {
        ops_gsbox(((c >> 0x10) & 0xff) * 8 + 2) ^
        ops_gsbox(((b >> 8) & 0xff) * 8 + 3) ^
        ops_gsbox((d >> 0x18) * 8 + 1) ^ \
        ops_gsbox((a & 0xff) * 8) ^ oinfo.m_ops_key.ops_ievc[5]
    };  //# 75CF3118
    quint i = {
        ops_gsbox(((d >> 0x10) & 0xff) * 8 + 2) ^
        ops_gsbox(((c >> 8) & 0xff) * 8 + 3) ^
        ops_gsbox((a >> 0x18) * 8 + 1) ^ \
        ops_gsbox((b & 0xff) * 8) ^ oinfo.m_ops_key.ops_ievc[6]
    };  //# 6AD3F5C4
    a = {
        ops_gsbox(((d >> 8) & 0xff) * 8 + 3) ^
        ops_gsbox(((a >> 0x10) & 0xff) * 8 + 2) ^
        ops_gsbox((b >> 0x18) * 8 + 1) ^ \
        ops_gsbox((c & 0xff) * 8) ^ oinfo.m_ops_key.ops_ievc[7]
    };  //# D99AC8FB

    quint g{8};
    qchar asbox_len = (oinfo.m_ops_key.ops_ievc[0x3c] - 2);
    for (qint f{0}; f < asbox_len; f++)
    {
        quint d{e >> 0x18};  //# 35
        quint m{h >> 0x10};  //# cf
        quint s{h >> 0x18};
        quint z{e >> 0x10};
        quint l{i >> 0x18};
        quint t{e >> 8};
        e = ops_gsbox(((i >> 0x10) & 0xff) * 8 + 2) ^ ops_gsbox(((h >> 8) & 0xff) * 8 + 3) ^ \
                ops_gsbox((a >> 0x18) * 8 + 1) ^ ops_gsbox((e & 0xff) * 8) ^ oinfo.m_ops_key.ops_ievc[g];  //# B67F2106, 82508918
        h = ops_gsbox(((a >> 0x10) & 0xff) * 8 + 2) ^ ops_gsbox(((i >> 8) & 0xff) * 8 + 3) ^ \
                ops_gsbox(d * 8 + 1) ^ ops_gsbox((h & 0xff) * 8) ^ oinfo.m_ops_key.ops_ievc[g + 1];  //# 85813F52
        i = ops_gsbox((z & 0xff) * 8 + 2) ^ ops_gsbox(((a >> 8) & 0xff) * 8 + 3) ^ \
                ops_gsbox(s * 8 + 1) ^ ops_gsbox((i & 0xff) * 8) ^ oinfo.m_ops_key.ops_ievc[g + 2];  //# C8022573
        a = ops_gsbox((t & 0xff) * 8 + 3) ^ ops_gsbox((m & 0xff) * 8 + 2) ^ \
                ops_gsbox(l * 8 + 1) ^ ops_gsbox((a & 0xff) * 8) ^ oinfo.m_ops_key.ops_ievc[g + 3];  //# AD34EC55
        g = g + 4;
        //    # a=6DB8AA0E
        //    # b=ABD51D58
        //    # c=AFCBAFFF
        //    # d=51
        //    # e=AC402324
        //    # h=B2D24440
        //    # i=CC2ADF24
        //    # t=510805
    }
    oinfo.m_ops_key.key_pair.clear();
    oinfo.m_ops_key.key_pair.push_back({quint((ops_gsbox(((i >> 0x10) & 0xff) * 8) & 0xff0000) ^
                                        (ops_gsbox(((h >> 8) & 0xff) * 8 + 1) & 0xff00) ^
                                        (ops_gsbox((a >> 0x18) * 8 + 3) & 0xff000000) ^
                                        (ops_gsbox((e & 0xff) * 8 + 2)) & 0xFF ^ oinfo.m_ops_key.ops_ievc[g])});
    oinfo.m_ops_key.key_pair.push_back({quint(((ops_gsbox(((a >> 0x10) & 0xff) * 8) & 0xff0000) ^
                                        (ops_gsbox(((i >> 8) & 0xff) * 8 + 1) & 0xff00) ^
                                        (ops_gsbox((e >> 0x18) * 8 + 3) & 0xff000000) ^
                                        (ops_gsbox((h & 0xff) * 8 + 2) & 0xFF) ^ oinfo.m_ops_key.ops_ievc[g + 3]))});
    oinfo.m_ops_key.key_pair.push_back({quint((ops_gsbox(((e >> 0x10) & 0xff) * 8) & 0xff0000) ^
                                        (ops_gsbox(((a >> 8) & 0xff) * 8 + 1) & 0xff00) ^
                                        (ops_gsbox((h >> 0x18) * 8 + 3) & 0xff000000) ^
                                        (ops_gsbox((i & 0xff) * 8 + 2) & 0xFF) ^ oinfo.m_ops_key.ops_ievc[g + 2])});
    oinfo.m_ops_key.key_pair.push_back({quint((ops_gsbox(((h >> 0x10) & 0xff) * 8) & 0xff0000) ^
                                        (ops_gsbox(((e >> 8) & 0xff) * 8 + 1) & 0xff00) ^
                                        (ops_gsbox((i >> 0x18) * 8 + 3) & 0xff000000) ^
                                        (ops_gsbox((a & 0xff) * 8 + 2) & 0xFF) ^ oinfo.m_ops_key.ops_ievc[g + 1])});
}

qbool OPSDecrypt::DecOpsData(OPSDeviceInfo &oinfo, qsizetype out_len, qbool enc)
{
    qtimer stimer{};
    stimer.restart();

    qbyte dec{};
    qsizetype len{oinfo.m_tmp_buff.size()};
    qsizetype idx{oinfo.m_tmp_buff.size()};
    for (qsizetype pos{0}; (pos<idx); (pos+=(0x10), (len-=(0x10))))
    {
        if (pos == 0)
            oinfo.m_ops_key.key_pair = {oinfo.m_ops_key.m_hdrkey};

        OPSGetKey(oinfo);
        quint tmp[4] = {};
        for (quint i{0}; i < 4; i++)
        {
            tmp[i] = {
                quint(oinfo.m_ops_key.key_pair[i] ^
                (*(quint_le*)oinfo.m_tmp_buff.mid((i*4) + pos, 4).data()))
            };

           // Instance()->send_progress(stimer, "Decryption", "Data", idx, pos);

            dec.push_back(qbyte((char*)&tmp[i], sizeof(tmp[i])));
        }

        for (quint i{0}; i < 4; i++)
        {
            oinfo.m_ops_key.key_pair[i] = {
                (enc?tmp[i] : (*(quint_le*)(oinfo.m_tmp_buff.mid((i*4) + pos, 4).data())))
            };
        }
    }
    if (idx % 0x10)
        dec.resize(dec.size() - (idx % 0x10));

    oinfo.m_tmp_buff.clear();
    oinfo.m_tmp_buff.push_back(dec);
    return {qbool(oinfo.m_tmp_buff.size())};
}

qbool OPSDecrypt::DecOpsFile(OPSDeviceInfo &oinfo, OPSEntry entry)
{
    std::function<qstr(quint64)> get_tr_speed = [&]
            (quint64 bytes)
    {        // According to the Si standard KB is 1000 bytes, KiB is 1024
        // but on windows sizes are calculated by dividing by 1024 so we do what they do.
        const quint64 kb = 1024;
        const quint64 mb = 1024 * kb;
        if (bytes >= mb)
            return QLocale().toString(bytes / (double)mb, 'f', 2) + "MB/S";
        if (bytes >= kb)
            return QLocale().toString(bytes / (double)kb, 'f', 2) + "KB/S";
        return QLocale().toString(bytes) + "B/S";
    };

    qfile out_dev(qstr("%0/%1").arg(oinfo.m_out_path, entry.m_fname));
    if (!out_dev.open(qiodev::WriteOnly | qiodev::Truncate))
        return(0);

    oinfo.m_ops_dev->reset();
    out_dev.reset();

    qlong offset{entry.m_offset.toULongLong()};
    if (!oinfo.m_ops_dev->seek(offset))
    {
        oinfo.m_ops_dev->close();
        out_dev.close();
        return(0);
    }

    qtimer stimer{};
    stimer.restart();

    qlong bwread{0};
    qlong maxlen{entry.m_tmplen};
    while (maxlen > 0)
    {
       // is_terminated();

        qint64 bread = qMinLen((qint64)maxlen, 0x1000000);
        qbyte wread = {oinfo.m_ops_dev->read(bread)};
        oinfo.m_tmp_buff = {wread};
        if (entry.m_decode)
        {
            if (!DecOpsData(oinfo))
            {
                oinfo.m_ops_dev->close();
                out_dev.close();
                return(0);
            }
        }

        if (!out_dev.write(oinfo.m_tmp_buff))
        {
            oinfo.m_ops_dev->close();
            out_dev.close();
            return(0);
        }

        qlong percent(((qreal)offset/entry.m_tmplen)*100);
          qlong trspeed(stimer.elapsed()? (offset*1000/stimer.elapsed()): 0xa);

        qInfo().noquote() << QString("Extracting[%0](%1/%2)...").arg(entry.m_pname,
                                                                     qstr::number((qreal)percent),
                                                                     get_tr_speed(trspeed));

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        QProcess::execute("cmd /c cls");


//        Instance()->send_progress(stimer,
//                                       "Extracting",
//                                       entry.m_pname,
//                                       entry.m_tmplen,
//                                       bwread);

        maxlen -= bread;
        bwread += bread;
        oinfo.m_tmp_buff.clear();
    }

    out_dev.close();
    return {static_cast<qbool>(out_dev.size())};
}

qbool OPSDecrypt::write_file(qstr path, qbyte data, qbool append = 0)
{
    qfile file(path);
    if (!append && file.exists())
        file.remove();

    if (!file.open(qiodev::WriteOnly | append?qiodev::Append : qiodev::Truncate))
        return 0;

    file.write(data);
    file.waitForBytesWritten(-1);
    file.close();

    return 1;
}

qvoid OPSDecrypt::UnpackOPS(QString ops_path)
{
    qInfo() << (qstr("Reading OPS file %0\n").arg(ops_path));

    qstr out_path = {
        qstr("%0/%1_%2").arg(qfileinfo(ops_path).absolutePath(),
        qfileinfo(ops_path).completeBaseName(),
        QUuid::createUuid().toString().mid(1, 8))
    };
    if (!qdir(out_path).exists())
        qdir(out_path).mkdir(".");

    QFile ops_dev(QDir::toNativeSeparators(ops_path));
    if (!ops_dev.open(qiodev::ReadOnly))
        return;

    ops_dev.reset();

    QVector<quint> ops_key{};
    ops_key.push_back(0x9ee3b5d1);
    ops_key.push_back(0x9d04ea5e);
    ops_key.push_back(0xabd51d67);
    ops_key.push_back(0xafcbafd2);

    QVector<QVector<qchar>> sboxs = {};
    sboxs.push_back({0x60,0x8a,0x3f,0x2d,0x68,0x6b,0xd4,0x23,0x51,0x0c,0xd0,0x95,0xbb,0x40,0xe9,0x76});//guacamoles_31_O.09_190820
    sboxs.push_back({0xaa,0x69,0x82,0x9e,0x5d,0xde,0xb1,0x3d,0x30,0xbb,0x81,0xa3,0x46,0x65,0xa3,0xe1});//instantnoodlev_15_o.07_201103
    sboxs.push_back({0xc4,0x5d,0x05,0x71,0x99,0xdd,0xbb,0xee,0x29,0xa1,0x6d,0xc7,0xad,0xbf,0xa4,0x3f});//guacamolet_21_o.08_190502

    OPSDeviceInfo oinfo = {};
    oinfo.m_ops_dev = {&ops_dev};
    oinfo.m_out_path = {out_path};
    oinfo.m_ops_key.m_hdrkey = {ops_key};

    qInfo("===== Extracting config file =====\n");

    for (QVector<QVector<qchar>>::iterator it = sboxs.begin();
         it != sboxs.end(); it++)
    {
        //is_terminated();

        QVector<qchar> mbox{*it};
        mbox.resize(0x3d);
        mbox.insert(0x3c, 0x0a);

        oinfo.m_ops_key.ops_ievc = (mbox);
        if (UnpackXML(oinfo))
            break;
        oinfo.m_ops_key.ops_ievc.clear();
    }

    if (!oinfo.m_xml_dev.size())
    {
        qInfo("Invalid ops file or unsupported encryption type!.");
        oinfo.m_ops_dev->close();
        return;
    }

    qsizetype blksz_idx = {
        oinfo.m_xml_dev.indexOf("SECTOR_SIZE_IN_BYTES=")
    };
    if (blksz_idx != -1/*0xffffffff*/)
    {
        oinfo.m_qc_blksz = {
            static_cast<qsizetype>(
            qstr{oinfo.m_xml_dev.mid(blksz_idx+0x16, 4)}.
            replace("\"", qstr()).toUInt())
        };
        qInfo("Sector size: ");
        qInfo() << (qstr().setNum(oinfo.m_qc_blksz, 0xa));
    }

    if (!GetOPSEntries(oinfo))
    {
        qInfo("No valid partitions found!.");
        oinfo.m_ops_dev->close();
        return;
    }

    qInfo("===== Extracting MSM Download Tool info =====\n");

    for (QMap<qstr,qstr>::iterator it =
         oinfo.m_ops_dl_info.begin();
         it != oinfo.m_ops_dl_info.end(); it++)
    {
        qstr key{it.key()};
        qstr val{it.value()};
        if (key.size() && val.size())
        {
            qInfo() << (qstr("%0: ").arg(key));
            qInfo() << (val);
        }
    }

    qInfo("===== Extracting ops partitions =====\n");

    for (QVector<OPSEntry>::iterator it = oinfo.m_entries.begin();
         it != oinfo.m_entries.end(); it++)
    {
      //  is_terminated();

        OPSEntry ops_entry{*it};

        qInfo() << (qstr("UnpackByID [%0](%1)... ").arg(
                            ops_entry.m_pname,
                            qstr().setNum(ops_entry.m_length, 0x10)));

        if (DecOpsFile(oinfo, ops_entry))
            qInfo("Ok");
        else
            qInfo("Failed!");
    }

    oinfo.m_ops_dev->close();

    qInfo() << (qstr("Firmware extracted to %0").arg(out_path));
    QDesktopServices::openUrl(QUrl::fromLocalFile(out_path));
}
