import React, {Component} from 'react';
import styles from './NavBar.module.css';
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

class NavDivider extends Component {
    render() {
        let className = cx(this.context, {
            divider: true
        });

        return (
            <span className={className}>

            </span>
        );
    }
}

NavDivider.propTypes = {};

export default NavDivider;