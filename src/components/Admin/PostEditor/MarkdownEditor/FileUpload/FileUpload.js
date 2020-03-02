import * as React from 'react';
import {Fragment} from 'react';
import PropTypes from 'prop-types';
import * as classNames from 'classnames/bind';

import {Alert, FileInput, FormGroup, H5, InputGroup} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons';
import {Intent} from '@blueprintjs/core/lib/cjs/common/intent';

import {ImageStore} from '../../../../../data/resource/image';

import styles from './FileUpload.module.css'

let cx = classNames.bind(styles);

class FileUpload extends React.Component {
    onDragEnter = (e) => {
        clearTimeout(this.timeout);
        this.timeout = setTimeout(() => {
            this.setState({
                dragging: false
            });
        }, 750);

        this.setState({
            dragging: true
        });
        e.preventDefault();
        e.stopPropagation();

    };
    onDrop = (e) => {
        if (!e) {
            return
        }

        e.stopPropagation();
        e.preventDefault();

        let file = e.nativeEvent.dataTransfer.files[0];
        if (!file) {
            return;
        }

        this.handleFile(file);
    };
    onSelectInputFile = (e) => {
        if (!e) {
            return
        }
        this.handleFile(e.target.files[0]);
        this.setState({
            fileName: e.target.files[0].name
        });
    };
    handleFile = (file) => {
        if (!file) {
            return;
        }
        if (!file.type.startsWith('image')) {
            this.setState({
                alert: 'mimetype',
                alertOpen: true
            });
            return;
        }

        const reader = new FileReader()

        reader.addEventListener('load', () => {
            let dataURL = reader.result;
            this.setState({
                fileObjectURL: dataURL,
                fileType: file.type,
                img: dataURL.slice(dataURL.indexOf('base64,') + 7),
                alert: 'preview',
                alertOpen: true
            })
        })

        reader.readAsDataURL(file)
    };

    copyMarkdown = () => {
        this.inputRef.select();
        document.execCommand('copy');
        this.inputRef.blur();
    };

    constructor(props) {
        super(props);
        this.uploadFile = this.uploadFile.bind(this);
        this.state = {};
    }

    render() {
        const dropArea = cx({
            'drag-area': true,
            'dragging': this.state.dragging
        });

        const childrenClass = cx({
            // 'hidden': this.state.dragging
        });

        return (
            <Fragment>
                <FormGroup label={'Upload an image'} inline={true} className={styles['file-upload-input']}>
                    <FileInput onInputChange={this.onSelectInputFile}/>
                </FormGroup>
                {this.renderAlert()}
                <div className={styles['container']} onDragOver={this.onDragEnter} onDrop={this.onDrop}>
                    <div className={dropArea}>
                        Drag image here to upload
                    </div>
                    <div className={childrenClass}>
                        {this.props.children}
                    </div>
                </div>
            </Fragment>
        )
    }

    uploadFile() {
        this.setState({
            alertOpen: false
        });
        ImageStore.add({
            title: this.state.imageTitle,
            contents: this.state.img
        }).then(value => {
            this.setState({
                alert: 'success',
                alertOpen: true,
                imageID: value.id,
                imageMarkdown: `![](${value.id})`
            });
        }).catch((err) => {
            console.error(err);
            this.setState({
                alert: 'error',
                alertOpen: true
            });
        })
    }

    renderAlert() {
        if (this.state.alert === 'mimetype') {
            return (
                <Alert
                    isOpen={this.state.alertOpen}
                    onConfirm={() => this.setState({alertOpen: false})}
                    intent={Intent.WARNING}
                    icon={IconNames.WARNING_SIGN}
                >
                    <H5>Invalid file type! File must be a valid image.</H5>
                </Alert>
            );
        }
        if (this.state.alert === 'preview') {
            return (
                <Alert
                    isOpen={this.state.alertOpen}
                    onConfirm={this.uploadFile}
                    confirmButtonText={'Upload'}
                    cancelButtonText={'Cancel'}
                    onCancel={() => this.setState({alertOpen: false})}
                    onClose={() => window.URL.revokeObjectURL(this.state.fileObjectURL)}
                    intent={Intent.PRIMARY}>
                    <object type={this.state.fileType} data={this.state.fileObjectURL} title={'Upload Preview'}/>
                    <H5 className={styles['alert-text']}>
                        <FormGroup label={'Image Title'} labelInfo={'(alt text)'}>
                            <InputGroup placeholder={'Image Title'} value={this.state.imageTitle}
                                        onChange={(val) => this.setState({imageTitle: val.target.value})}/>
                        </FormGroup>
                    </H5>
                </Alert>
            )
        }
        if (this.state.alert === 'success') {
            return (
                <Alert
                    isOpen={this.state.alertOpen}
                    onConfirm={this.copyMarkdown}
                    confirmButtonText={'Copy to Clipboard'}
                    cancelButtonText={'Close'}
                    onCancel={() => this.setState({alertOpen: false})}
                    icon={IconNames.TICK}
                    intent={Intent.SUCCESS}>
                    <H5 className={styles['alert-text']}>
                        Success! The image markdown is: <InputGroup className={styles['alert-text']}
                                                                    onChange={() => {
                                                                    }}
                                                                    value={this.state.imageMarkdown}
                                                                    inputRef={(e) => this.inputRef = e}/>
                    </H5>
                </Alert>
            )
        }
        if (this.state.alert === 'error') {
            return (
                <Alert
                    isOpen={this.state.alertOpen}
                    confirmButtonText={'Close'}
                    onConfirm={() => this.setState({alertOpen: false})}
                    icon={IconNames.ERROR}
                    intent={Intent.DANGER}>
                    <H5>
                        An error occurred when uploading this file. The error has been logged.
                    </H5>
                </Alert>
            )
        }
    }
}

FileUpload.propTypes = {
    src: PropTypes.string,
    children: PropTypes.oneOfType([PropTypes.arrayOf(PropTypes.element), PropTypes.element])
};

export default FileUpload;