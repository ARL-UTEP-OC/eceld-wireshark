/* packet_comment_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_COMMENT_DIALOG_H
#define PACKET_COMMENT_DIALOG_H

#include <glib.h>
#include <qglobal.h>
#include <QPushButton>
#include <QString>
#include <QLabel>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QPlainTextEdit>
#include "packet_address_info.h"
#include <QFileDialog>
#include <QPixmap>
#include <QUrl>

#include "geometry_state_dialog.h"

namespace Ui {
class PacketCommentDialog;
}

class PacketCommentDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit PacketCommentDialog(guint32 frame, QWidget *parent = 0, QString comment = QString(), QString filterText = QString(), QString keypresses = QString(), QString systemcalls = QString(), QString pkt_ascii = QString(), QString pkt_hex = QString(), QString filePath = QString());
    ~PacketCommentDialog();
    QString text();

public slots:
    void on_buttonBox_helpRequested();
    void on_scopeComboBox_currentIndexChanged(int currentIndex);
    void on_importantPacketIdentifierComboBox_currentIndexChanged(int currentIndex);
    void on_screenshotsPushButton_clicked();
    void on_screenshotsCurrentChanged(QString path);
    void on_viewScreenshotPushButton_clicked();
    void on_clearLastScreenshotPushButton_clicked();

private slots:
    void copyComment();
    void pasteComment(guint32 frame, QString comment);
    void requestComment();
    void clearCurrentComment();
    void deleteCurrentComment();
    void handleAcceptSignal();
    void handleRejectSignal();
    void pasteKeypresses();
    void pasteSystemcalls();
    void pasteAscii();
    void pasteHex();

signals:
    void copyPacketComment(QString comment);
    void pastePacketComment(guint32 frame);
    void sendAccept(guint32 frame, QString comment);
    void sendReject(guint32 frame, bool deleteCommentContents);

private:
    Ui::PacketCommentDialog *pc_ui_;
    int scopeLastIndex;
    int importantIdLastIndex;
    guint32 thisFrame;
    QString mainFilterText;
    std::string packetRangeText;
    QString packetRangeStartText;
    QString packetRangeEndText;
    QString suricataText;
    QString importantPacketIdentifierText;
    QLabel *filterLabel;
    QLineEdit *filterLineEdit;
    QLabel *packetRangeLabel;
    QLineEdit *packetRangeStartLineEdit;
    QLineEdit *packetRangeEndLineEdit;
    QHBoxLayout *packetRangesLayout;
    QLabel *suricataLabel;
    QLineEdit *suricataLineEdit;
    QMessageBox *invalidFormatMessageBox;
    QString keypresses;
    QString systemcalls;
    packet_address_info *pinfo;
    QString pkt_ascii;
    QString pkt_hex;
    QPushButton *asciiPushButton;
    QPushButton *hexPushButton;
    QPlainTextEdit *ipiPlainTextEdit;
    QVBoxLayout *ipiVerticalLayout;
    QHBoxLayout *ipiHorizontalLayout;
    QString fp;
    QFileDialog *screenshotBrowser;
    QLabel *imagePreview;
    QPixmap pixmap;
    QString file;
    QStringList files;
    QSize thumbnailSize;
    QString lastFilePath;


    bool deleteComment;
    void setupDynamicElements();
    void setupStaticElements(QString kp, QString sc, QString filePath);
    std::vector<std::string> splitComment(QString comment);
    void populateWidgets(std::vector<std::string> tokens);
    void clearWidgets();
    void setupScreenshotBrowser(QString subdir);
    QString shortenFilePath(QString filePath);
    QString showScreenshot();
};

#endif // PACKET_COMMENT_DIALOG_H
