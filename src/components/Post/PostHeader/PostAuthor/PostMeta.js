import React from 'react';
import {Classes} from '@blueprintjs/core'
import {css, StyleSheet} from 'aphrodite';
import PropTypes from 'prop-types';
import dayjs from 'dayjs';

class PostMeta extends React.PureComponent {
    render() {
        if (this.props.loading) {
            return (
                <div className={this.props.className}>
                    <div className={css(styles.skeleton, styles.container) + ' ' + Classes.SKELETON}/>
                </div>
            );
        }

        return (
            <div className={this.props.className + ' ' + css(styles.container)}>
                <span>Posted on </span>
                <span title={this.getFormattedToolTip()}>
                    {this.getCreatedDateElement()}
                </span>
                <span> by </span>
                <span className={css(styles.author)}>
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

const styles = StyleSheet.create({
    container: {
        marginBottom: '15px',
        fontStyle: 'italic'
    },
    skeleton: {
        width: '200px',
        height: '20px',
        marginLeft: 'auto',
        marginRight: 'auto'
    },
    author: {
        marginBottom: '15px'
    }
});

PostMeta.propTypes = {
    containerClassName: PropTypes.string,
    className: PropTypes.string,
    author: PropTypes.any,
    createdTime: PropTypes.instanceOf(Date),
    modifiedTime: PropTypes.instanceOf(Date),
    loading: PropTypes.bool
};

export default PostMeta;