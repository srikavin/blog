import React, {Component} from 'react';
import PropTypes from 'prop-types';
import styles from './Skeleton.module.css'
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

class Skeleton extends Component {
    render() {
        let classes = cx({
            skeleton: true,
            left: this.props.align === 'left',
            center: this.props.align === 'center',
            right: this.props.align === 'right'
        });

        if (this.props.children) {
            return React.Children.map(this.props.children, child => {
                let className = classNames(child.props ? child.props.className : undefined, classes, this.props.className);

                if (typeof (child) === 'string') {
                    return <p
                        className={className}>{child}</p>
                }
                return (
                    React.cloneElement(child, {
                        className: className
                    })
                )
            });
        }

        return (
            <div className={classes}>
                <div className={this.props.className}/>
            </div>
        )
    }
}

Skeleton.propTypes = {
    children: PropTypes.oneOfType([PropTypes.array, PropTypes.node]),
    align: PropTypes.oneOf(['center', 'left', 'right', 'none']),
    className: PropTypes.string
};

export default Skeleton;