import React, {Component} from 'react';
import PropTypes from 'prop-types';
import styles from './NavBar.module.css';
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

class NavBar extends Component {
    render() {
        let classes = cx({
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