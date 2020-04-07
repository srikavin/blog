import React, {Component} from 'react';
import {FaMoon, FaRegSun} from "react-icons/fa";
import {LIGHT_THEME, ThemeContext} from "../Theme";
import styles from './ThemeSelector.module.css'
import classNames from 'classnames/bind'

let cx = classNames.bind(styles)

class ThemeSelector extends Component {
    constructor(props) {
        super(props);
        this.state = {
            value: 'light'
        };

        const query = window.matchMedia('(prefers-color-scheme: dark)')

        if (query.matches) {
            this.state.value = 'dark'
        }

        query.onchange = (q) => {
            if (q.matches) {
                this.setState({
                    value: 'dark'
                })
            } else {
                this.setState({
                    value: 'light'
                })
            }
        }

        this.onClick = this.onClick.bind(this);
    }

    onClick() {
        if (this.state.value === 'dark') {
            this.setState({
                value: 'light'
            })
        } else {
            this.setState({
                value: 'dark'
            })
        }
    }

    render() {
        return (
            <>
                <ThemeContext.Provider value={this.state.value}>
                    {this.props.children}
                </ThemeContext.Provider>
                <div className={cx('selector', this.state.value)} onClick={this.onClick}>
                    <span className={styles.icon}>{this.state.value === LIGHT_THEME ? <FaRegSun/> : <FaMoon/>}</span>
                    <br/>
                    {this.state.value === LIGHT_THEME ? 'Light' : 'Dark'}
                </div>
            </>
        );
    }
}

export default ThemeSelector;