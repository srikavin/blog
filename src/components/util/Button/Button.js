import * as React from 'react';
import {Component} from 'react';
import PropTypes from 'prop-types';

import styles from './Button.module.css';
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

export class Button extends Component {
    onClick() {
        if (this.props.onClick) {
            this.props.onClick();
        }
    }

    render() {
        let btnClass = cx({
            button: true,
            minimal: this.props.minimal,
            hasIcon: this.props.icon
        });

        let iconClass = cx({
            icon: true
        });

        return (
            <button className={btnClass} type="button" onClick={() => this.onClick()}>
                {this.props.icon ? (
                    <span className={iconClass}>
                    {this.props.icon}
                </span>
                ) : null}
                {this.props.children ? this.props.children : this.props.text}
            </button>
        );
    }
}

Button.propTypes = {
    children: PropTypes.array,
    minimal: PropTypes.bool,
    onClick: PropTypes.func,
    icon: PropTypes.node
};