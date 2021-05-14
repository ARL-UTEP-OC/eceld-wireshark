#include <file_dialog_preview.h>
#include <QFileDialog>

/*
    Constructor
*/
FileDialogPreview::FileDialogPreview(QWidget *parent, QString directory) :
    QFileDialog(parent, "Select a screenshot", directory, "*.*"),
    file_dialog_(new FileDialogPreview)
{
    printf("FDP: start of constructor\n");
    file_dialog_->setOption(QFileDialog::DontUseNativeDialog, true);
    file_dialog_->setFixedSize((file_dialog_->width() + 250), file_dialog_->height());
    //file_dialog_->setFileMode(QFileDialog::AnyFile);
    //file_dialog_->setWindowFlags(Qt::Widget);

    printf("FDP: set options\n");
    
    imagePreview = new QLabel("Preview", this);
    imagePreview->setFixedSize(250, 250);
    imagePreview->setAlignment(Qt::AlignCenter);
    imagePreview->setObjectName("imagePreview");

    printf("FDP: set image preview\n");

    box = new QVBoxLayout();
    box->addWidget(imagePreview);
    box->addStretch();

    printf("FDP: added image preview to box layout\n");

    file_dialog_->layout()->addItem(box);

    printf("FDP: added box layout to file dialog window\n");

    file = QString();
    files = QStringList();
    thumbnailSize = QSize(250, 250);
    selectedFilePath = QString();

    QObject::connect(this, SIGNAL(currentChanged(QString)), this, SLOT(on_currentChanged(QString)));
    QObject::connect(this, SIGNAL(fileSelected(QString)), this, SLOT(on_fileSelected(QString)));
    QObject::connect(this, SIGNAL(filesSelected(QStringList)), this, SLOT(on_filesSelected(QStringList)));
    QObject::connect(this, SIGNAL(accepted()), this, SLOT(handleAcceptSignal()));

    printf("FDP: connected all signals/slots\n");
}

FileDialogPreview::~FileDialogPreview() {
    delete file_dialog_;
}

void FileDialogPreview::on_currentChanged(QString path) {
    selectedFilePath = path;
    pixmap = QPixmap(path);

    if (pixmap.isNull()) {
        imagePreview->setText("Preview");
    }
    else {
        imagePreview->setPixmap(pixmap.scaled(thumbnailSize, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
}

void FileDialogPreview::on_fileSelected(QString selectedFile) {
    file = selectedFile;
}

void FileDialogPreview::on_filesSelected(QStringList selectedFiles) {
    files = selectedFiles;
}

void FileDialogPreview::handleAcceptSignal() {
    
}