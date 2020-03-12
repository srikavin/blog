import * as React from 'react';
import PropTypes from 'prop-types';
import {ImageStore} from '../../../../../data/resource/image';

import classNames from 'classnames/bind';
import styles from './ImageRenderer.module.css'

let cx = classNames.bind(styles);

class ImageRenderer extends React.Component {
    constructor(props) {
        super(props);
        this.state = {};
    }

    defaults = {
        'image-position': 'center',
        'image-width': 'auto',
        'image-height': 'auto'
    };

    componentDidMount() {
        if (isValidURL(this.props.src)) {
            this.setState({
                url: this.props.src,
                title: this.props.alt,
                blur: false
            });
        } else {
            ImageStore.getById(this.props.src).then(value => {
                this.setState({
                    title: this.props.alt || value.title,
                    width: value.width,
                    height: value.height,
                    fileType: value.fileType,
                });

                if (value.contents) {
                    this.setState({
                        url: value.contents,
                        blur: false
                    });
                } else {
                    this.setState({
                        url: 'data:img/png;base64,' + value.small,
                        blur: true
                    });
                    ImageStore.resolveFull(value).then(e => {
                        this.setState({
                            url: e.contents,
                            blur: false
                        });
                    });
                }

            });
        }
    }

    render() {
        let settings;
        if (this.props.settings) {
            settings = Object.assign({}, this.defaults, this.props.settings);
        }

        let imgStyles = cx({
            'post-img': true,
        });

        let styles = {
            'float': settings["image-position"],
            'blur': this.state.blur,
            'max-width': '100%'
        };

        return (
            <span className={imgStyles}>
                {this.state.blur ? (
                    <img height='auto'
                         width={this.state.width}
                         src={this.state.url}
                         style={styles}
                         alt={this.state.title}/>
                ) : (
                    <object height={settings['image-height']}
                            width={settings['image-width']}
                            type={this.state.fileType}
                            data={this.state.url}
                            style={styles}
                    >{this.state.title}</object>
                )}
            </span>
        )

    }
}

let isValidURL = (string) => {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
};

ImageRenderer.propTypes = {
    src: PropTypes.string,
    settings: PropTypes.object
};

export default ImageRenderer;