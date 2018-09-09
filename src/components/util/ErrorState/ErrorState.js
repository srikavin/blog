import React, {Component} from 'react';
import PropTypes from 'prop-types';

import styles from './ErrorState.module.css';
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

class ErrorState extends Component {
    render() {
        const {icon, action, children, description, title} = this.props;

        let classNames = cx({
            error: true
        });

        return (
            <div className={classNames}>
                {icon ? icon : null}
                <h4>{title}</h4>
                <div>
                    {description}
                </div>
                {action}
                {children}
            </div>
        );
    }
}

ErrorState.propTypes = {
    action: PropTypes.node,
    children: PropTypes.array,
    description: PropTypes.node,
    icon: PropTypes.node,
    title: PropTypes.node
};

export default ErrorState;