import React, {Component} from 'react';
import PropTypes from 'prop-types';
import styles from './NavBar.module.css';
import classNames from 'classnames/bind';
import {ThemeContext} from "../../Theme";

let cx = classNames.bind(styles);

class NavBar extends Component {
    static contextType = ThemeContext

    render() {
        let classes = cx(this.context, {
            navbar: true
        });

        return (
            <nav className={classes}>
                {this.props.children}
            </nav>
        );
    }
}


NavBar.propTypes = {
    children: PropTypes.arrayOf(PropTypes.node)
};

export default NavBar;