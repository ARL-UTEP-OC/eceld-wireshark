/* packet_comment_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_comment_dialog.h"
#include <ui_packet_comment_dialog.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <ui/qt/utils/stock_icon.h>
#include "wireshark_application.h"
#include <cstddef>

/*
    Constructor
*/
PacketCommentDialog::PacketCommentDialog(guint32 frame, QWidget *parent, QString comment, QString filterText, QString kp, QString sc, QString pktascii, QString pkthex, QString filePath) :
    GeometryStateDialog(parent, Qt::Window),
    pc_ui_(new Ui::PacketCommentDialog)
{
    //Update the title of the window with the frame number of the current selected packet
    QString title = QString(tr("Packet %1 Comment"))
                              .arg(frame);

    //Variable initialization
    thisFrame = frame;
    mainFilterText = filterText;
    pkt_ascii = pktascii;
    pkt_hex = pkthex;
    std::string fp = filePath.toStdString();
    std::string directory;
    std::string parentDirectory;
    std::size_t last_slash_idx = fp.rfind('/');
    if (last_slash_idx != std::string::npos) {
        directory = fp.substr(0, last_slash_idx);
    }
    last_slash_idx = directory.rfind('/');
    if (last_slash_idx != std::string::npos) {
        parentDirectory = directory.substr(0, last_slash_idx);
    }
    pc_ui_->setupUi(this);
    loadGeometry();
    setWindowTitle(wsApp->windowTitleString(title));
    setupStaticElements(kp, sc, QString(parentDirectory.c_str()));
    setupDynamicElements();
    
    //Signal-Slot connections required for various functions:
    //-- load dynamic content based on user selection,
    //-- copy-paste mechanism
    //-- handling packet comment text (writing to pcap, deleting comment from pcap)
    QObject::connect(pc_ui_->scopeComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(on_scopeComboBox_currentIndexChanged(int)), Qt::UniqueConnection);
    QObject::connect(pc_ui_->importantPacketIdentifierComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(on_importantPacketIdentifierComboBox_currentIndexChanged(int)), Qt::UniqueConnection);
    QObject::connect(pc_ui_->actionCopyCurrentPacket, SIGNAL(triggered()), this, SLOT(copyComment()), Qt::UniqueConnection);
    QObject::connect(this, SIGNAL(copyPacketComment(QString)), parent, SLOT(copyCurrentPacketComment(QString)), Qt::UniqueConnection);
    QObject::connect(pc_ui_->actionPasteStoredPacket, SIGNAL(triggered()), this, SLOT(requestComment()), Qt::UniqueConnection);
    QObject::connect(this, SIGNAL(pastePacketComment(guint32)), parent, SLOT(pasteStoredComment(guint32)), Qt::UniqueConnection);
    QObject::connect(parent, SIGNAL(sendStoredComment(guint32, QString)), this, SLOT(pasteComment(guint32, QString)), Qt::UniqueConnection);
    QObject::connect(pc_ui_->actionClearCurrentComment, SIGNAL(triggered()), this, SLOT(clearCurrentComment()), Qt::UniqueConnection);
    QObject::connect(pc_ui_->buttonBox->button(QDialogButtonBox::Reset), SIGNAL(clicked()), this, SLOT(deleteCurrentComment()), Qt::UniqueConnection);
    QObject::connect(pc_ui_->buttonBox->button(QDialogButtonBox::Cancel), SIGNAL(clicked()), this, SIGNAL(rejected()), Qt::UniqueConnection);
    QObject::connect(this, SIGNAL(rejected()), this, SLOT(handleRejectSignal()), Qt::UniqueConnection);
    QObject::connect(pc_ui_->buttonBox->button(QDialogButtonBox::Ok), SIGNAL(clicked()), this, SLOT(handleAcceptSignal()), Qt::UniqueConnection);
    QObject::connect(this, SIGNAL(sendAccept(guint32, QString)), parent, SLOT(handlePCDAcceptSignal(guint32, QString)), Qt::UniqueConnection);
    QObject::connect(this, SIGNAL(sendReject(guint32, bool)), parent, SLOT(handlePCDRejectSignal(guint32, bool)), Qt::UniqueConnection);
    QObject::connect(pc_ui_->keypressesPushButton, SIGNAL(clicked()), this, SLOT(pasteKeypresses()), Qt::UniqueConnection);
    QObject::connect(pc_ui_->systemcallsPushButton, SIGNAL(clicked()), this, SLOT(pasteSystemcalls()), Qt::UniqueConnection);
    QObject::connect(asciiPushButton, SIGNAL(clicked()), this, SLOT(pasteAscii()), Qt::UniqueConnection);
    QObject::connect(hexPushButton, SIGNAL(clicked()), this, SLOT(pasteHex()), Qt::UniqueConnection);
    QObject::connect(pc_ui_->screenshotsPushButton, SIGNAL(clicked()), this, SLOT(on_screenshotsPushButton_clicked()), Qt::UniqueConnection);
    QObject::connect(pc_ui_->viewScreenshotPushButton, SIGNAL(clicked()), this, SLOT(on_viewScreenshotPushButton_clicked()), Qt::UniqueConnection);
    QObject::connect(pc_ui_->clearLastScreenshotPushButton, SIGNAL(clicked()), this, SLOT(on_clearLastScreenshotPushButton_clicked()), Qt::UniqueConnection);

    //Parse the comment passed in as a parameter, and then populate the appropriate widgets
    populateWidgets(splitComment(comment));
    
    if(comment != NULL) {
        pc_ui_->buttonBox->button(QDialogButtonBox::Reset)->setEnabled(true);
    }
    else {
        pc_ui_->buttonBox->button(QDialogButtonBox::Reset)->setEnabled(false);
    }
}

/*
    De-constructor
*/
PacketCommentDialog::~PacketCommentDialog()
{
    delete pc_ui_;
}

void PacketCommentDialog::setupStaticElements(QString kp, QString sc, QString filePath) {
    //pinfo = new packet_address_info();
    packetRangeText = "";
    suricataText = QString("");
    importantPacketIdentifierText = QString("");
    scopeLastIndex = -1;
    importantIdLastIndex = -1;
    QStringList scopes = {"", "Single Packet", "Conversation", "Filter", "Packet Range", "Suricata Attribute Value"};
    pc_ui_->scopeComboBox->addItems(scopes);
    QStringList identifiers = {"", "Entire Packet Payload", "Custom Identifier"};
    pc_ui_->importantPacketIdentifierComboBox->addItems(identifiers);
    QStringList confidences = {"", "1", "2", "3"};
    pc_ui_->confidenceComboBox->addItems(confidences);
    deleteComment = false;
    pc_ui_->buttonBox->button(QDialogButtonBox::Reset)->setText("Delete Comment");
    packetRangeStartText = QString(tr("%1")).arg(thisFrame);
    packetRangeEndText = QString("");
    invalidFormatMessageBox = new QMessageBox(this);
    invalidFormatMessageBox->setText("Invalid Comment\n\nThe Scope and Important Packet Identifier fields\nmust be non-empty.");
    invalidFormatMessageBox->setIcon(QMessageBox::Critical);
    keypresses = kp;
    systemcalls = sc;
    if (kp.isEmpty()) {
        pc_ui_->keypressesPushButton->setEnabled(false);
    }
    if (sc.isEmpty()) {
        pc_ui_->systemcallsPushButton->setEnabled(false);
    }
    fp = filePath;
    //thumbnail size for the preview section in the screenshot browser
    thumbnailSize = QSize(500, 500);
}

/*
    Initializes the variables for the dynamic content.
    Also adds some placeholder text to some text fields.
    Sets all dynamic content to hidden, by default.
*/
void PacketCommentDialog::setupDynamicElements() {
    filterLabel = new QLabel(this);
    filterLabel->setObjectName(QString("filterLabel"));
    filterLabel->setText(QString("Filter:"));
    filterLineEdit = new QLineEdit(this);
    filterLineEdit->setObjectName(QString("filterLineEdit"));
    filterLineEdit->setText(mainFilterText);
    packetRangeLabel = new QLabel(this);
    packetRangeLabel->setObjectName(QString("packetRangeLabel"));
    packetRangeLabel->setText(QString("Packet Range:"));
    packetRangeStartLineEdit = new QLineEdit(this);
    packetRangeStartLineEdit->setObjectName(QString("packetRangeStartLineEdit"));
    packetRangeStartLineEdit->setPlaceholderText(QString("Start"));
    packetRangeStartLineEdit->setText(packetRangeStartText);
    packetRangeEndLineEdit = new QLineEdit(this);
    packetRangeEndLineEdit->setObjectName(QString("packetRangeEndLineEdit"));
    packetRangeEndLineEdit->setPlaceholderText(QString("End"));
    packetRangesLayout = new QHBoxLayout();
    packetRangesLayout->setObjectName(QString("packetRangesLayout"));
    packetRangesLayout->addWidget(packetRangeStartLineEdit);
    packetRangesLayout->addWidget(packetRangeEndLineEdit);
    suricataLabel = new QLabel(this);
    suricataLabel->setObjectName(QString("suricataLabel"));
    suricataLabel->setText(QString("Suricata Attribute Value:"));
    suricataLabel->setMaximumSize(QSize(150, 16777215));
    suricataLabel->setWordWrap(true);
    suricataLineEdit = new QLineEdit(this);
    suricataLineEdit->setObjectName(QString("filterLineEdit"));
    suricataLineEdit->setPlaceholderText(QString("Enter Suricata attribute value(s) here"));
    pc_ui_->descriptionPlainTextEdit->setPlaceholderText(QString("Enter description text here"));
    pc_ui_->cmdPlainTextEdit->setPlaceholderText(QString("Enter corresponding command here"));
    pc_ui_->programLineEdit->setPlaceholderText(QString("Enter corresponding program here"));
    ipiVerticalLayout = new QVBoxLayout();
    ipiVerticalLayout->setObjectName(QStringLiteral("ipiVerticalLayout"));
    ipiPlainTextEdit = new QPlainTextEdit(this);
    ipiPlainTextEdit->setObjectName(QStringLiteral("ipiPlainTextEdit"));
    ipiPlainTextEdit->setPlaceholderText("Enter packet identifier here");
    ipiVerticalLayout->addWidget(ipiPlainTextEdit);
    ipiHorizontalLayout = new QHBoxLayout();
    ipiHorizontalLayout->setObjectName(QStringLiteral("ipiHorizontalLayout"));
    asciiPushButton = new QPushButton(this);
    asciiPushButton->setObjectName(QStringLiteral("asciiPushButton"));
    asciiPushButton->setText(QStringLiteral("Add ASCII"));
    hexPushButton = new QPushButton(this);
    hexPushButton->setObjectName(QStringLiteral("hexPushButton"));
    hexPushButton->setText(QStringLiteral("Add Hex"));
    ipiHorizontalLayout->addWidget(asciiPushButton);
    ipiHorizontalLayout->addWidget(hexPushButton);
    ipiVerticalLayout->addLayout(ipiHorizontalLayout);

    filterLabel->hide();
    filterLineEdit->hide();
    packetRangeLabel->hide();
    packetRangeStartLineEdit->hide();
    packetRangeEndLineEdit->hide();
    suricataLabel->hide();
    suricataLineEdit->hide();
    ipiPlainTextEdit->hide();
    asciiPushButton->hide();
    hexPushButton->hide();
}

/*
    Returns a single-line representation of the packet comment.
    Current delimiter between fields can be modified.
*/
QString PacketCommentDialog::text()
{
    QString result = QString(""),
        delimiter = QString("**"),
        subtagDelimiter = QString(";"),
        scopeTag = QString("scope="), 
        singleTag = QString("single"),
        conversationTag = QString("conversation"),
        filterTag = QString("filter;"),
        packetRangeTag = QString("packet-range;"),
        suricataTag = QString("suricata;"),
        ipiTag = QString("important-packet-identifier="),
        packetPayloadTag = QString("all-packet-payload"),
        programUsedTag = QString("program-used="),
        cmdTag = QString("cmd="),
        descriptionTag = QString("description="),
        confidenceTag = QString("confidence="),
        lastScreenshotTag = QString("lastScreenshot="),
        advancedTag = QString("advanced="),
        srcMACTag = QString("srcMACAddress"),
        dstMACTag = QString("dstMACAddress"),
        srcIPTag = QString("srcIPAddress"),
        dstIPTag = QString("dstIPAddress"),
        srcPortTag = QString("srcPort"),
        dstPortTag = QString("dstPort"),
        ingressTag = QString("ingress"),
        egressTag = QString("egress"),
        bothDirTag = QString("bothDir"),
        suricataRuleTag = QString("customSuricataRule=");

    //If the user has not defined a scope, skip
    if (pc_ui_->scopeComboBox->currentIndex() > 0) {
        int index = pc_ui_->scopeComboBox->currentIndex();

        switch (index) {
            case 1: result.append(scopeTag + singleTag + delimiter); break;
            case 2: result.append(scopeTag + conversationTag + delimiter); break;
            case 3: result.append(scopeTag + filterTag + filterLineEdit->text() + delimiter); break;
            case 4: {
                //Ensure the text field is non-empty
                if (packetRangeStartLineEdit->text().length() > 0) {
                    if (packetRangeEndLineEdit->text().length() > 0) {
                        result.append(scopeTag + packetRangeTag + packetRangeStartLineEdit->text() + QString("-") + packetRangeEndLineEdit->text() + delimiter); break;
                    }
                    else {
                        result.append(scopeTag + packetRangeTag + packetRangeStartLineEdit->text() + delimiter); break;
                    }
                }
                else if (packetRangeEndLineEdit->text().length() > 0) {
                    result.append(scopeTag + packetRangeTag + packetRangeEndLineEdit->text() + delimiter); break;
                }
                break;
            }
            case 5: {
                //Ensure the text field is non-empty
                if (suricataLineEdit->text().length() > 0) {
                    result.append(scopeTag + suricataTag + suricataLineEdit->text() + delimiter); break;
                }
                break;
            }
            default: break;
        }
    }
    
    //If the user has defined a packet identifier
    if (pc_ui_->importantPacketIdentifierComboBox->currentIndex() > 0) {
        int index = pc_ui_->importantPacketIdentifierComboBox->currentIndex();

        switch (index) {
            case 1: result.append(ipiTag + packetPayloadTag + delimiter); break;
            case 2: {
                //Ensure the text field is non-empty
                if (ipiPlainTextEdit->toPlainText().length() > 0) {
                    result.append(ipiTag + ipiPlainTextEdit->toPlainText() + delimiter); break;
                }
                break;
            }
            default: break;
        }
    }

    //If the user has defined a program that generated the current packet
    if (pc_ui_->programLineEdit->text().length() > 0) {
        result.append(programUsedTag + pc_ui_->programLineEdit->text() + delimiter);
    }

    //If the user has defined a command that generated the current packet
    if (pc_ui_->cmdPlainTextEdit->toPlainText().length() > 0) {
        result.append(cmdTag + pc_ui_->cmdPlainTextEdit->toPlainText() + delimiter);
    }

    //If the user has provided a description for the packet
    if (pc_ui_->descriptionPlainTextEdit->toPlainText().length() > 0) {
        result.append(descriptionTag + pc_ui_->descriptionPlainTextEdit->toPlainText() + delimiter);
    }

    //If the user has provided a confidence score for the packet
    if (pc_ui_->confidenceComboBox->currentIndex() > 0) {
        result.append(confidenceTag + pc_ui_->confidenceComboBox->currentText() + delimiter);
    }

    //If there is a previously associated screenshot with this packet
    if(pc_ui_->lastScreenshotLabel->text() != "None") {
        result.append(lastScreenshotTag + pc_ui_->lastScreenshotLabel->text() + delimiter);
    }

    //ADVANCED TAB

    //Check all preservation check boxes in the Advanced tab
    bool advancedTagAdded = false;
    if(pc_ui_->srcMACCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + srcMACTag);
        }
        else {
            result.append(subtagDelimiter + srcMACTag);
        }
    }
    if(pc_ui_->dstMACCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + dstMACTag);
        }
        else {
            result.append(subtagDelimiter + dstMACTag);
        }
    }
    if(pc_ui_->srcIPCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + srcIPTag);
        }
        else {
            result.append(subtagDelimiter + srcIPTag);
        }
    }
    if(pc_ui_->dstIPCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + dstIPTag);
        }
        else {
            result.append(subtagDelimiter + dstIPTag);
        }
    }
    if(pc_ui_->srcPortCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + srcPortTag);
        }
        else {
            result.append(subtagDelimiter + srcPortTag);
        }
    }
    if(pc_ui_->dstPortCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + dstPortTag);
        }
        else {
            result.append(subtagDelimiter + dstPortTag);
        }
    }
    if(pc_ui_->ingressCheckBox->isChecked() && pc_ui_->egressCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + bothDirTag);
        }
        else {
            result.append(subtagDelimiter + bothDirTag);
        }
    }
    else if(pc_ui_->ingressCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + ingressTag);
        }
        else {
            result.append(subtagDelimiter + ingressTag);
        }
    }
    else if(pc_ui_->egressCheckBox->isChecked()) {
        if (!advancedTagAdded) {
            advancedTagAdded = true;
            result.append(advancedTag + egressTag);
        }
        else {
            result.append(subtagDelimiter + egressTag);
        }
    }
    
    if(advancedTagAdded) {
        result.append(delimiter);
    }

    //If the user has provided a custom suricata rule for the packet
    if (pc_ui_->suricataRulePlainTextEdit->toPlainText().length() > 0) {
        result.append(suricataRuleTag + pc_ui_->suricataRulePlainTextEdit->toPlainText() + delimiter);
    }

    //If the packet comment contains any fields, remove the trailing delimiter
    if (result.length() > 0) {
        result.remove(result.length() - 2, 2);
    }
    
    return result;
}

/*
    Splits the single-line comment into a vector of tokens.
    Current assumed delimiter between fields can be modified.
*/
std::vector<std::string> PacketCommentDialog::splitComment(QString comment) {
    std::string c = comment.toStdString();
    std::string delimiter = "**";
    std::size_t pos_start = 0, pos_end, delim_length = delimiter.length();
    std::string token;
    std::vector<std::string> result;

    while ((pos_end = c.find(delimiter, pos_start)) != std::string::npos) {
        token = c.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_length;
        result.push_back(token);
    }
    result.push_back(c.substr(pos_start));

    return result;
}

/*
    Populates the appropriate widgets based on the vector of tokens provided by the
    passed-in comment.
*/
void PacketCommentDialog::populateWidgets(std::vector<std::string> tokens) {
    std::size_t tagLength;
    char scopeTag[] = "scope=", 
        singleTag[] = "single",
        conversationTag[] = "conversation",
        filterTag[] = "filter;",
        packetRangeTag[] = "packet-range;",
        suricataTag[] = "suricata;",
        ipiTag[] = "important-packet-identifier=",
        packetPayloadTag[] = "all-packet-payload",
        programUsedTag[] = "program-used=",
        cmdTag[] = "cmd=",
        descriptionTag[] = "description=",
        confidenceTag[] = "confidence=",
        lastScreenshotTag[] = "lastScreenshot=",
        intervalDash[] = "-",
        advancedTag[] = "advanced=",
        srcMACTag[] = "srcMACAddress",
        dstMACTag[] = "dstMACAddress",
        srcIPTag[] = "srcIPAddress",
        dstIPTag[] = "dstIPAddress",
        srcPortTag[] = "srcPort",
        dstPortTag[] = "dstPort",
        ingressTag[] = "ingress",
        egressTag[] = "egress",
        bothDirTag[] = "bothDir",
        suricataRuleTag[] = "customSuricataRule=";

    for (auto i : tokens) {
        if (i.find(scopeTag) != std::string::npos) {
            if (i.find(singleTag) != std::string::npos) {
                pc_ui_->scopeComboBox->setCurrentIndex(1);
            }
            else if (i.find(conversationTag) != std::string::npos) {
                pc_ui_->scopeComboBox->setCurrentIndex(2);
            }
            else if (i.find(filterTag) != std::string::npos) {
                tagLength = sizeof(scopeTag) + sizeof(filterTag) - 2;
                mainFilterText = QString((i.substr(tagLength, i.length() - tagLength)).c_str());
                filterLineEdit->setText(mainFilterText);
                pc_ui_->scopeComboBox->setCurrentIndex(3);
            }
            else if (i.find(packetRangeTag) != std::string::npos) {
                tagLength = sizeof(scopeTag) + sizeof(packetRangeTag) - 2;
                packetRangeText = i.substr(tagLength, i.length() - tagLength);
                if (packetRangeText.find(intervalDash) != std::string::npos) {
                    tagLength = packetRangeText.find(intervalDash);
                    packetRangeStartText = QString((packetRangeText.substr(0, tagLength)).c_str());
                    tagLength++;
                    packetRangeEndText = QString((packetRangeText.substr(tagLength, packetRangeText.length() - tagLength)).c_str());
                    packetRangeStartLineEdit->setText(packetRangeStartText);
                    packetRangeEndLineEdit->setText(packetRangeEndText);
                }
                else {
                    packetRangeStartLineEdit->setText(QString(packetRangeText.c_str()));
                }
                pc_ui_->scopeComboBox->setCurrentIndex(4);
            }
            else if (i.find(suricataTag) != std::string::npos) {
                tagLength = sizeof(scopeTag) + sizeof(suricataTag) - 2;
                suricataText = QString((i.substr(tagLength, i.length() - tagLength)).c_str());
                suricataLineEdit->setText(suricataText);
                pc_ui_->scopeComboBox->setCurrentIndex(5);
            }
        }
        else if(i.find(ipiTag) != std::string::npos) {
            if (i.find(packetPayloadTag) != std::string::npos) {
                pc_ui_->importantPacketIdentifierComboBox->setCurrentIndex(1);
            }
            else {
                tagLength = sizeof(ipiTag) - 1;
                importantPacketIdentifierText = QString((i.substr(tagLength, i.length() - tagLength)).c_str());
                ipiPlainTextEdit->setPlainText(importantPacketIdentifierText);
				if(importantPacketIdentifierText.length()==0) {
					pc_ui_->importantPacketIdentifierComboBox->setCurrentIndex(0);
				}
				else {
					pc_ui_->importantPacketIdentifierComboBox->setCurrentIndex(2);
				}
            }
        }
        else if(i.find(programUsedTag) != std::string::npos) {
            tagLength = sizeof(programUsedTag) - 1;
            pc_ui_->programLineEdit->setText(QString((i.substr(tagLength, i.length() - tagLength)).c_str()));
        }
        else if(i.find(cmdTag) != std::string::npos) {
            tagLength = sizeof(cmdTag) - 1;
            pc_ui_->cmdPlainTextEdit->setPlainText(QString((i.substr(tagLength, i.length() - tagLength)).c_str()));
        }
        else if(i.find(descriptionTag) != std::string::npos) {
            tagLength = sizeof(descriptionTag) - 1;
            pc_ui_->descriptionPlainTextEdit->setPlainText(QString((i.substr(tagLength, i.length() - tagLength)).c_str()));
        }
        else if(i.find(confidenceTag) != std::string::npos) {
            if (i.find("1") != std::string::npos) {
                pc_ui_->confidenceComboBox->setCurrentIndex(1);
            }
            else if (i.find("2") != std::string::npos) {
                pc_ui_->confidenceComboBox->setCurrentIndex(2);
            }
            else if (i.find("3") != std::string::npos){
                pc_ui_->confidenceComboBox->setCurrentIndex(3);
            }
            else {
                pc_ui_->confidenceComboBox->setCurrentIndex(0);
            }
        }
        else if (i.find(lastScreenshotTag) != std::string::npos) {
            tagLength = sizeof(lastScreenshotTag) - 1;
            pc_ui_->lastScreenshotLabel->setText(QString((i.substr(tagLength, i.length() - tagLength)).c_str()));
        }
        else if(i.find(advancedTag) != std::string::npos) {
            if(i.find(srcMACTag) != std::string::npos) {
                pc_ui_->srcMACCheckBox->setChecked(true);
            }
            if(i.find(dstMACTag) != std::string::npos) {
                pc_ui_->dstMACCheckBox->setChecked(true);
            }
            if(i.find(srcIPTag) != std::string::npos) {
                pc_ui_->srcIPCheckBox->setChecked(true);
            }
            if(i.find(dstIPTag) != std::string::npos) {
                pc_ui_->dstIPCheckBox->setChecked(true);
            }
            if(i.find(srcPortTag) != std::string::npos) {
                pc_ui_->srcPortCheckBox->setChecked(true);
            }
            if(i.find(dstPortTag) != std::string::npos) {
                pc_ui_->dstPortCheckBox->setChecked(true);
            }
            if(i.find(ingressTag) != std::string::npos) {
                pc_ui_->ingressCheckBox->setChecked(true);
            }
            if(i.find(egressTag) != std::string::npos) {
                pc_ui_->egressCheckBox->setChecked(true);
            }
            if(i.find(bothDirTag) != std::string::npos) {
                pc_ui_->ingressCheckBox->setChecked(true);
                pc_ui_->egressCheckBox->setChecked(true);
            }
        }
        else if(i.find(suricataRuleTag) != std::string::npos) {
            tagLength = sizeof(suricataRuleTag) - 1;
            pc_ui_->suricataRulePlainTextEdit->setPlainText(QString((i.substr(tagLength, i.length() - tagLength)).c_str()));
        }
    }
}

void PacketCommentDialog::clearWidgets() {
    pc_ui_->scopeComboBox->setCurrentIndex(0);
    pc_ui_->importantPacketIdentifierComboBox->setCurrentIndex(0);
    pc_ui_->confidenceComboBox->setCurrentIndex(0);
    pc_ui_->programLineEdit->clear();
    pc_ui_->cmdPlainTextEdit->clear();
    pc_ui_->descriptionPlainTextEdit->clear();
    filterLineEdit->clear();
    packetRangeStartLineEdit->clear();
    packetRangeEndLineEdit->clear();
    suricataLineEdit->clear();
    ipiPlainTextEdit->clear();
    pc_ui_->srcMACCheckBox->setChecked(false);
    pc_ui_->dstMACCheckBox->setChecked(false);
    pc_ui_->srcIPCheckBox->setChecked(false);
    pc_ui_->dstIPCheckBox->setChecked(false);
    pc_ui_->srcPortCheckBox->setChecked(false);
    pc_ui_->dstPortCheckBox->setChecked(false);
    pc_ui_->ingressCheckBox->setChecked(false);
    pc_ui_->egressCheckBox->setChecked(false);
    pc_ui_->suricataRulePlainTextEdit->clear();
}

/*
    Slot function provided by the Wireshark devs. Currently does nothing,
    so it's unclear why it's still here.
*/
void PacketCommentDialog::on_buttonBox_helpRequested()
{
//    wsApp->helpTopicAction(HELP_PACKET_COMMENT_DIALOG);
}

/*
    Slot function that sends the current comment to the main window for it to be stored.
    This comment will be provided whenever a paste signal is encountered.
*/
void PacketCommentDialog::copyComment() {
    //printf("PCD: Sending copy of comment\n");
    QString comment = text();
    emit copyPacketComment(comment);
}

/*
    Slot function that receives the stored comment from the main window and populates the
    current window with its value.
*/
void PacketCommentDialog::pasteComment(guint32 frame, QString comment) {
    if (frame == thisFrame) {
        if (comment != NULL || comment != "") {
            //printf("PCD(%i): Pasting comment\n", thisFrame);
            populateWidgets(splitComment(comment));
        }
    }
}

/*
    Slot function to request the current stored comment from the main window.
*/
void PacketCommentDialog::requestComment() {
    //printf("PCD: Requesting stored comment\n");
    emit pastePacketComment(thisFrame);
}

/*
    Slot function to load dynamic content into the window based on user selection
    within the scope field.
*/
void PacketCommentDialog::on_scopeComboBox_currentIndexChanged(int currentIndex) {
    if (currentIndex == scopeLastIndex) {
        return;
    }

    //If the previous index pertained to a selection with dynamic content,
    //remove that content from the window.
    //Must re-initialize variables after, since removeRow() actually deletes
    //said variables.
    switch (scopeLastIndex) {
        case 3: {
            pc_ui_->packetCommentFormLayout->removeRow(1);
            filterLabel = new QLabel(this);
            filterLabel->setObjectName(QString("filterLabel"));
            filterLabel->setText(QString("Filter:"));
            filterLineEdit = new QLineEdit(this);
            filterLineEdit->setObjectName(QString("filterLineEdit"));
            filterLineEdit->setText(mainFilterText);
            filterLabel->setVisible(false);
            filterLineEdit->setVisible(false);
            break;
        }
        case 4: {
            pc_ui_->packetCommentFormLayout->removeRow(1);
            packetRangeLabel = new QLabel(this);
            packetRangeLabel->setObjectName(QString("packetRangeLabel"));
            packetRangeLabel->setText(QString("Packet Range:"));
            packetRangeStartLineEdit = new QLineEdit(this);
            packetRangeStartLineEdit->setObjectName(QString("packetRangeStartLineEdit"));
            packetRangeStartLineEdit->setPlaceholderText(QString("Start"));
            packetRangeStartLineEdit->setText(packetRangeStartText);
            packetRangeEndLineEdit = new QLineEdit(this);
            packetRangeEndLineEdit->setObjectName(QString("packetRangeEndLineEdit"));
            packetRangeEndLineEdit->setPlaceholderText(QString("End"));
            packetRangeEndLineEdit->setText(packetRangeEndText);
            packetRangesLayout = new QHBoxLayout();
            packetRangesLayout->setObjectName(QString("packetRangesLayout"));
            packetRangesLayout->addWidget(packetRangeStartLineEdit);
            packetRangesLayout->addWidget(packetRangeEndLineEdit);
            packetRangeLabel->setVisible(false);
            packetRangeStartLineEdit->setVisible(false);
            packetRangeEndLineEdit->setVisible(false);
            break;
        }
        case 5: {
            pc_ui_->packetCommentFormLayout->removeRow(1);
            suricataLabel = new QLabel(this);
            suricataLabel->setObjectName(QString("suricataLabel"));
            suricataLabel->setText(QString("Suricata Attribute Value:"));
            suricataLabel->setMaximumSize(QSize(70, 16777215));
            suricataLabel->setWordWrap(true);
            suricataLineEdit = new QLineEdit(this);
            suricataLineEdit->setObjectName(QString("suricataLineEdit"));
            suricataLineEdit->setPlaceholderText(QString("Enter Suricata attribute value(s) here"));
            suricataLineEdit->setText(suricataText);
            suricataLabel->setVisible(false);
            suricataLineEdit->setVisible(false);
            break;
        }
        default: break;
    }
    
    //Add the appropriate dynamic content to the window in the correct row
    switch (currentIndex) {
        case 3: {
            pc_ui_->packetCommentFormLayout->insertRow(1, filterLabel, filterLineEdit);
            filterLabel->setVisible(true);
            filterLineEdit->setVisible(true);
            break;
        }
        case 4: {
            pc_ui_->packetCommentFormLayout->insertRow(1, packetRangeLabel, packetRangesLayout);
            packetRangeLabel->setVisible(true);
            packetRangeStartLineEdit->setVisible(true);
            packetRangeEndLineEdit->setVisible(true);
            break;
        }
        case 5: {
            pc_ui_->packetCommentFormLayout->insertRow(1, suricataLabel, suricataLineEdit);
            suricataLabel->setVisible(true);
            suricataLineEdit->setVisible(true);
            break;
        }
        default: break;
    }

    scopeLastIndex = currentIndex;
}

/*
    Slot function to load dynamic content into the window based on user selection
    within the importantPacketIdentifier field.
*/
void PacketCommentDialog::on_importantPacketIdentifierComboBox_currentIndexChanged(int currentIndex) {
    if (currentIndex == importantIdLastIndex) {
        return;
    }

    //If the previous index pertained to a selection with dynamic content,
    //remove that content from the window.
    //Must re-initialize variables after, since removeRow() actually deletes
    //said variables.
    if (importantIdLastIndex == 2) {
        //Account for the case when the user currently has dynamic content loaded for the scope field
        if (3 <= pc_ui_->scopeComboBox->currentIndex() && pc_ui_->scopeComboBox->currentIndex()<= 5) {
            pc_ui_->packetCommentFormLayout->removeRow(3);
            ipiVerticalLayout = new QVBoxLayout();
            ipiVerticalLayout->setObjectName(QStringLiteral("ipiVerticalLayout"));
            ipiPlainTextEdit = new QPlainTextEdit(this);
            ipiPlainTextEdit->setObjectName(QStringLiteral("ipiPlainTextEdit"));
            ipiPlainTextEdit->setPlaceholderText("Enter packet identifier here");
            ipiPlainTextEdit->setPlainText(importantPacketIdentifierText);
            ipiVerticalLayout->addWidget(ipiPlainTextEdit);
            ipiHorizontalLayout = new QHBoxLayout();
            ipiHorizontalLayout->setObjectName(QStringLiteral("ipiHorizontalLayout"));
            asciiPushButton = new QPushButton(this);
            asciiPushButton->setObjectName(QStringLiteral("asciiPushButton"));
            asciiPushButton->setText(QStringLiteral("Add ASCII"));
            hexPushButton = new QPushButton(this);
            hexPushButton->setObjectName(QStringLiteral("hexPushButton"));
            hexPushButton->setText(QStringLiteral("Add Hex"));
            ipiHorizontalLayout->addWidget(asciiPushButton);
            ipiHorizontalLayout->addWidget(hexPushButton);
            ipiVerticalLayout->addLayout(ipiHorizontalLayout);
            ipiPlainTextEdit->setVisible(false);
            asciiPushButton->setVisible(false);
            hexPushButton->setVisible(false);
            QObject::connect(asciiPushButton, SIGNAL(clicked()), this, SLOT(pasteAscii()), Qt::UniqueConnection);
            QObject::connect(hexPushButton, SIGNAL(clicked()), this, SLOT(pasteHex()), Qt::UniqueConnection);
        }
        else {
            pc_ui_->packetCommentFormLayout->removeRow(2);
            ipiVerticalLayout = new QVBoxLayout();
            ipiVerticalLayout->setObjectName(QStringLiteral("ipiVerticalLayout"));
            ipiPlainTextEdit = new QPlainTextEdit(this);
            ipiPlainTextEdit->setObjectName(QStringLiteral("ipiPlainTextEdit"));
            ipiPlainTextEdit->setPlaceholderText("Enter packet identifier here");
            ipiPlainTextEdit->setPlainText(importantPacketIdentifierText);
            ipiVerticalLayout->addWidget(ipiPlainTextEdit);
            ipiHorizontalLayout = new QHBoxLayout();
            ipiHorizontalLayout->setObjectName(QStringLiteral("ipiHorizontalLayout"));
            asciiPushButton = new QPushButton(this);
            asciiPushButton->setObjectName(QStringLiteral("asciiPushButton"));
            asciiPushButton->setText(QStringLiteral("Add ASCII"));
            hexPushButton = new QPushButton(this);
            hexPushButton->setObjectName(QStringLiteral("hexPushButton"));
            hexPushButton->setText(QStringLiteral("Add Hex"));
            ipiHorizontalLayout->addWidget(asciiPushButton);
            ipiHorizontalLayout->addWidget(hexPushButton);
            ipiVerticalLayout->addLayout(ipiHorizontalLayout);
            ipiPlainTextEdit->setVisible(false);
            asciiPushButton->setVisible(false);
            hexPushButton->setVisible(false);
            QObject::connect(asciiPushButton, SIGNAL(clicked()), this, SLOT(pasteAscii()), Qt::UniqueConnection);
            QObject::connect(hexPushButton, SIGNAL(clicked()), this, SLOT(pasteHex()), Qt::UniqueConnection);
        }
    }

    //Add the appropriate dynamic content to the window in the correct row
    if (currentIndex == 2) {
        //Account for the case when the user currently has dynamic content loaded for the scope field
        if (3 <= pc_ui_->scopeComboBox->currentIndex() && pc_ui_->scopeComboBox->currentIndex()<= 5) {
            pc_ui_->packetCommentFormLayout->insertRow(3, new QLabel(""), ipiVerticalLayout);
            ipiPlainTextEdit->setVisible(true);
            asciiPushButton->setVisible(true);
            hexPushButton->setVisible(true);
        }
        else {
            pc_ui_->packetCommentFormLayout->insertRow(2, new QLabel(""), ipiVerticalLayout);
            ipiPlainTextEdit->setVisible(true);
            asciiPushButton->setVisible(true);
            hexPushButton->setVisible(true);
        }
    }

    importantIdLastIndex = currentIndex;
}

void PacketCommentDialog::clearCurrentComment() {
    //printf("PCD: Clearing comment\n");
    clearWidgets();
}

void PacketCommentDialog::deleteCurrentComment(){
    //printf("PCD: Deleting comment\n");
    deleteComment = true;
    emit reject();
}

void PacketCommentDialog::handleAcceptSignal() {
    bool acceptComment = true;
    int currentIndex = pc_ui_->importantPacketIdentifierComboBox->currentIndex();
    
    switch(currentIndex) {
        case 0: {
            invalidFormatMessageBox->exec();
            acceptComment = false;
            break;
        }
        case 2: {
            if (ipiPlainTextEdit->toPlainText().isEmpty()) {
                invalidFormatMessageBox->exec();
                acceptComment = false;
                break;
            }
            break;
        }
        default: break;
    }
    
    currentIndex = pc_ui_->scopeComboBox->currentIndex();

    switch(currentIndex) {
        case 0: {
            if(acceptComment) {
                invalidFormatMessageBox->exec();
                acceptComment = false;
                break;
            }
            break;
        }
        case 3: {
            if (filterLineEdit->text().isEmpty()) {
                if (acceptComment) {
                    invalidFormatMessageBox->exec();
                    acceptComment = false;
                    break;
                }
            }
            break;
        }
        case 4: {
            if (packetRangeStartLineEdit->text().isEmpty() && packetRangeEndLineEdit->text().isEmpty()) {
                if (acceptComment) {
                    invalidFormatMessageBox->exec();
                    acceptComment = false;
                    break;
                }
            }
            break;
        }
        case 5: {
            if (suricataLineEdit->text().isEmpty()) {
                if(acceptComment) {
                    invalidFormatMessageBox->exec();
                    acceptComment = false;
                    break;
                }
            }
            break;
        }
        default: break;
    }
    
    if (acceptComment) {
        emit sendAccept(thisFrame, text());
        emit accepted();
    }
}

void PacketCommentDialog::handleRejectSignal() {
    emit sendReject(thisFrame, deleteComment);
}

void PacketCommentDialog::pasteKeypresses() {
    pc_ui_->cmdPlainTextEdit->setPlainText(pc_ui_->cmdPlainTextEdit->toPlainText() + keypresses);
}

void PacketCommentDialog::pasteSystemcalls() {
    pc_ui_->cmdPlainTextEdit->setPlainText(pc_ui_->cmdPlainTextEdit->toPlainText() + systemcalls);
}

void PacketCommentDialog::pasteAscii() {
    ipiPlainTextEdit->setPlainText(ipiPlainTextEdit->toPlainText() + pkt_ascii + "\n");
}

void PacketCommentDialog::pasteHex() {
    ipiPlainTextEdit->setPlainText(ipiPlainTextEdit->toPlainText() + pkt_hex + "\n");
}

void PacketCommentDialog::setupScreenshotBrowser(QString subdir) {
    screenshotBrowser = new QFileDialog(NULL, "Select a screenshot", fp+subdir, "*.*");
    screenshotBrowser->setOption(QFileDialog::DontUseNativeDialog, true);
    screenshotBrowser->setMinimumSize(800, 500);

    imagePreview = new QLabel("Preview", this);
    imagePreview->setFixedSize(thumbnailSize);
    imagePreview->setAlignment(Qt::AlignCenter);
    imagePreview->setObjectName("imagePreview");

    QGridLayout *screenshotLayout = qobject_cast <QGridLayout *>(screenshotBrowser->layout());
    screenshotLayout->addWidget(imagePreview, 1, 4);

    QObject::connect(screenshotBrowser, SIGNAL(currentChanged(QString)), this, SLOT(on_screenshotsCurrentChanged(QString)));
}

void PacketCommentDialog::on_screenshotsCurrentChanged(QString path) {
    pixmap = QPixmap(path);

    if (pixmap.isNull()) {
        imagePreview->setText("Preview");
    }
    else {
        imagePreview->setPixmap(pixmap.scaled(thumbnailSize, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
}

QString PacketCommentDialog::showScreenshot() {
    QUrl url;
    QString result;
    if (screenshotBrowser->exec() == QDialog::Accepted) {
        url = screenshotBrowser->selectedUrls().value(0);
    }
    else {
        url = QUrl();
    }

    if (url.isLocalFile() || url.isEmpty()) {
        result = url.toLocalFile();
    }
    else {
        result = url.toString();
    }

    return result;
}

void PacketCommentDialog::on_screenshotsPushButton_clicked() {
    bool createScreenshotWindow = true;
    QMessageBox *msgBox = new QMessageBox(this);
    msgBox->setInformativeText("Please select the type of screenshots to view");
    QPushButton *cancelButton = msgBox->addButton(QMessageBox::Cancel);
    QPushButton *clickButton = msgBox->addButton(tr("Click Events"), QMessageBox::ActionRole);
    QPushButton *timedButton = msgBox->addButton(tr("Timed Events"), QMessageBox::ActionRole);
    msgBox->resize(QSize(700, 200));

    msgBox->exec();

    if (msgBox->clickedButton() == clickButton) {
        setupScreenshotBrowser(QString("/Clicks"));
    }
    else if (msgBox->clickedButton() == timedButton) {
        setupScreenshotBrowser(QString("/Timed"));
    }
    else if (msgBox->clickedButton() == cancelButton) {
        createScreenshotWindow = false;
    }
    
    if (createScreenshotWindow) {
        QString filePath = showScreenshot();
        if (filePath != "") {
            std::string command = std::string("xdg-open ") + filePath.toStdString();
            int result = system(command.c_str());
            if (result == -1) {
                printf("Command failed: %i\n", result);
            }
            pc_ui_->lastScreenshotLabel->setText(shortenFilePath(filePath));
        }
        delete screenshotBrowser;
    }
}

QString PacketCommentDialog::shortenFilePath(QString filePath) {
    std::string fp = filePath.toStdString();
    std::string directory;
    std::string shortenedFp;
    std::size_t last_slash_idx = fp.rfind('/');
    if (last_slash_idx != std::string::npos) {
        directory = fp.substr(0, last_slash_idx);
    }
    last_slash_idx = directory.rfind('/');
    if (last_slash_idx != std::string::npos) {
        shortenedFp = fp.substr((last_slash_idx+1), (fp.length()-1));
    }

    return QString(shortenedFp.c_str());
}

void PacketCommentDialog::on_viewScreenshotPushButton_clicked() {
    if(pc_ui_->lastScreenshotLabel->text() != "None") {
        QString filePath = fp + QString("/") + pc_ui_->lastScreenshotLabel->text();
        std::string command = std::string("xdg-open ") + filePath.toStdString();
        int result = system(command.c_str());
        if (result == -1) {
            printf("Command failed: %i\n", result);
        }
    }
}

void PacketCommentDialog::on_clearLastScreenshotPushButton_clicked() {
    bool clearScreenshot = false;
    QMessageBox *msgBox = new QMessageBox(this);
    msgBox->setInformativeText("Are you sure you want to clear the last associated screenshot?");
    QPushButton *cancelButton = msgBox->addButton(QMessageBox::Cancel);
    QPushButton *okButton = msgBox->addButton(QMessageBox::Ok);

    msgBox->exec();

    if (msgBox->clickedButton() == okButton) {
        clearScreenshot = true;
    }
    else if(msgBox->clickedButton() == cancelButton) {
        //do nothing
    }

    if(clearScreenshot) {
        pc_ui_->lastScreenshotLabel->setText("None");
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

