import * as React from 'react';
import PropTypes from 'prop-types';
import {ImageStore} from '../../../../../data/resource/image';
import SVG from 'react-inlinesvg';

import classNames from 'classnames/bind';
import styles from './ImageRenderer.module.css'
import {ThemeContext} from "../../../../Theme";

let cx = classNames.bind(styles);

class ImageRenderer extends React.Component {
    static contextType = ThemeContext

    defaults = {
        'image-position': 'center',
        'image-width': 'none',
        'image-height': 'none'
    };

    constructor(props) {
        super(props);
        this.state = {
            imageRef: React.createRef(),
            observer: new IntersectionObserver(this.loadFullImage, {root: null, rootMargin: '0px', threshold: 0})
        };
    }

    componentWillUnmount() {
        this.state.observer.disconnect();
    }

    loadFullImage = (items) => {
        items.forEach(e => {
            if (!e.isIntersecting) {
                return;
            }

            if (this.state.blur === false) {
                return;
            }

            ImageStore.resolveFull(this.state.value).then(val => {
                this.setState({
                    url: val.contents,
                    blur: false
                });
            });
        });
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
                    height: value.height,
                    fileType: value.fileType,
                    value,
                    ...(value.contents ? {
                        url: value.contents,
                        blur: false
                    } : {
                        url: 'data:img/png;base64,' + value.small,
                        blur: true
                    })
                });
            });
        }
    }

    componentDidUpdate() {
        if (this.state.blur) {
            this.state.observer.observe(this.state.imageRef.current);
        } else {
            this.state.observer.disconnect();
        }
    }

    render() {
        let settings;
        if (this.props.settings) {
            settings = Object.assign({}, this.defaults, this.props.settings);
        }

        let containerClasses = cx(this.context, {
            'post-img': true,
        });

        let imgClasses = cx(this.context, {
            'blur': this.state.blur,
            'svg': this.state.fileType === 'image/svg+xml'
        })


        let styles = {
            'float': settings["image-position"],
        };

        if (settings['image-height'] === 'none') {
            settings['image-height'] = 'auto';
        }

        if (settings['image-width'] === 'none') {
            settings['image-width'] = 'auto';
        }

        if (this.state.blur) {
            return (
                <span className={containerClasses}>
                    <img src={this.state.url}
                         ref={this.state.imageRef}
                         height={this.state.height}
                         width={this.state.width}
                         className={imgClasses}
                         style={styles}
                         alt={this.state.title}/>
                </span>
            )
        }

        return (
            <span className={containerClasses}>
                {this.state.fileType === 'image/svg+xml' ? (
                    <SVG type={this.state.fileType}
                         preProcessor={(code) => {
                             return code.replace(/[Â]/g, '&nbsp')
                         }}
                         src={this.state.url}
                         className={imgClasses}
                         style={styles}
                    >{this.state.title}</SVG>
                ) : (<img src={this.state.url}
                          alt={this.state.title}
                          height={settings['image-height']}
                          width={settings['image-width']}
                          className={imgClasses}
                          style={styles}/>
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
