import React, {Component} from 'react';
import PropTypes from 'prop-types';
import styles from './NavBar.module.css';
import classNames from 'classnames/bind';
import NavBar from './NavBar';

let cx = classNames.bind(styles);

class NavGroup extends Component {
    render() {
        let className = cx({
            group: true,
            left: this.props.align === 'left',
            right: this.props.align === 'right'
        });

        return (
            <div className={className}>
                {this.props.children}
            </div>
        );
    }
}

NavBar.defaultProps = {
    align: 'left'
};

NavGroup.propTypes = {
    children: PropTypes.node,
    align: PropTypes.oneOf(['left', 'right'])
};

export default NavGroup;