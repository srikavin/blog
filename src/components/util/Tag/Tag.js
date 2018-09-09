import React, {Component} from 'react';
import PropTypes from 'prop-types';
import classNames from 'classnames/bind';
import styles from './Tag.module.css'

let cx = classNames.bind(styles);

class Tag extends Component {
    render() {
        let tagClass = cx({
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