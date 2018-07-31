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
        console.log(props);
    }

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
                    height: value.height
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
        let imgStyles = cx({
            'post-img': true,
            'blur': this.state.blur
        });
        return (
            <img width={this.state.width} height={this.state.height} src={this.state.url} className={imgStyles}
                 alt={this.state.title}/>
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
    src: PropTypes.string
};

export default ImageRenderer;