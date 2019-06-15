import React from 'react';
import PropTypes from 'prop-types';
import dayjs from 'dayjs';

import styles from './PostMeta.module.css'
import classNames from 'classnames/bind';
import Skeleton from '../../../util/Skeleton/Skeleton';

class PostMeta extends React.PureComponent {
    render() {
        if (this.props.loading) {
            return (
                <div className={this.props.className}>
                    <Skeleton align='center' className={classNames(styles.skeleton, styles.container)}/>
                </div>
            );
        }

        return (
            <div className={classNames(this.props.className, styles.container)}>
                <span>Posted on </span>
                <span title={this.getFormattedToolTip()}>
                    {this.getCreatedDateElement()}
                </span>
                <span> by </span>
                <span className={styles.author}>
                    {this.props.author.username}
                </span>
            </div>
        )
    }

    isModified() {
        return this.props.modifiedTime - this.props.createdTime > 10000;
    }

    getFormattedToolTip() {
        return `Created: ${dayjs(this.props.createdTime).toISOString()}` +
            (this.isModified() ? `\nLast modified: ${dayjs(this.props.modifiedTime).toISOString()}` : '')
    }

    getCreatedDateElement() {
        return dayjs(this.props.createdTime).format('MMMM D, YYYY') + (this.isModified() ? '*' : '');
    }
}

PostMeta.propTypes = {
    containerClassName: PropTypes.string,
    className: PropTypes.string,
    author: PropTypes.any,
    createdTime: PropTypes.instanceOf(Date),
    modifiedTime: PropTypes.instanceOf(Date),
    loading: PropTypes.bool
};

export default PostMeta;