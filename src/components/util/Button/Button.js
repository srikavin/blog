import * as React from 'react';
import {Component} from 'react';
import PropTypes from 'prop-types';

import styles from './Button.module.css';
import classNames from 'classnames/bind';
import {ThemeContext} from "../../Theme";

let cx = classNames.bind(styles);

export class Button extends Component {
    static contextType = ThemeContext

    onClick() {
        if (this.props.onClick) {
            this.props.onClick();
        }
    }

    render() {
        let btnClass = cx(this.context, {
            button: true,
            minimal: this.props.minimal,
            hasIcon: this.props.icon
        });

        let iconClass = cx(this.context, {
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