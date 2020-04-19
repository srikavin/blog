import React, {Component} from 'react';
import PropTypes from 'prop-types';
import classNames from 'classnames/bind';
import styles from './Tag.module.css'
import {ThemeContext} from "../../Theme";

let cx = classNames.bind(styles);

class Tag extends Component {
    static contextType = ThemeContext

    render() {
        let tagClass = cx(this.context, {
            tag: true,
            minimal: this.props.minimal,
            interactive: this.props.interactive
        });

        return (
            <span className={tagClass}>
                {this.props.children}
            </span>
        );
    }
}

Tag.propTypes = {
    minimal: PropTypes.bool,
    interactive: PropTypes.bool
};

export default Tag;