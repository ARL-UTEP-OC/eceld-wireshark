#ifndef FILE_DIALOG_PREVIEW_H
#define FILE_DIALOG_PREVIEW_H

#include <glib.h>
#include <qglobal.h>
#include <QFileDialog>
#include <QLabel>
#include <QVBoxLayout>
#include <QPixmap>
#include <QString>
#include <QStringList>
#include <QSize>

namespace Ui {
class FileDialogPreview;
}

class FileDialogPreview : public QFileDialog 
{
    Q_OBJECT

public:
    explicit FileDialogPreview(QWidget *parent = 0, QString directory = QString());
    ~FileDialogPreview();

private:
    FileDialogPreview *file_dialog_;
    QLabel *imagePreview;
    QVBoxLayout *box;
    QPixmap pixmap;
    QString file;
    QStringList files;
    QSize thumbnailSize;
    QString selectedFilePath;

private slots:
    void on_currentChanged(QString path);
    void on_fileSelected(QString selectedFile);
    void on_filesSelected(QStringList selectedFiles);
    void handleAcceptSignal();
};

#endif //FILE_DIALOG_PREVIEW_H