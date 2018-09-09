import React, {Component} from 'react';
import PropTypes from 'prop-types';
import styles from './NavBar.module.css';
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

class NavHeader extends Component {
    render() {
        let classNames = cx({
            heading: true
        });

        return (
            <div className={classNames}>
                {this.props.children}
            </div>
        );
    }
}

NavHeader.propTypes = {
    children: PropTypes.node
};

export default NavHeader;