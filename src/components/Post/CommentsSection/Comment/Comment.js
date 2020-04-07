import React from 'react';
import PropTypes from 'prop-types';

import Skeleton from '../../../util/Skeleton/Skeleton';
import type {CommentSchema} from "../../../../data/resource/post";

import styles from './Comment.module.css'
import dayjs from "dayjs";
import MarkdownRender from "../../PostContent/MathRenderer/MathRenderer";
import {ThemeContext} from "../../../Theme";

class Comment extends React.Component {
    static contextType = ThemeContext

    constructor() {
        super();
        this.ref = React.createRef();
    }

    handleReplyTo() {
        this.props.replyTo(this.props.id, this.props.username, this.ref);
    }

    render() {
        if (this.props.loading) {
            return (
                <div className={styles.comment}>
                    <Skeleton>
                        <div className={styles.picture_col} style={{'marginTop': 0}}/>
                    </Skeleton>
                    <Skeleton>
                        <div className={styles['content-wrapper-skeleton']}/>
                    </Skeleton>
                </div>
            )
        }

        return (
            <div ref={this.ref} className={styles.comment + ' ' + styles[`level-${this.props.level}`]}>
                <div className={styles.picture_col}>
                    <img src={this.props.gravatarUrl} className={styles.profile_picture}
                         alt={`Profile of ${this.props.username}`}/>
                </div>
                <div className={styles.content_wrapper}>
                    <div className={styles.header}>
                        <h3 className={styles.name}>{this.props.username}</h3>
                        <small className={styles.date}>{dayjs(this.props.createdTime).format('MMMM D, YYYY')}</small>
                    </div>
                    <MarkdownRender source={this.props.contents} className={styles.content}/>
                    <div className={styles.reply}><a onClick={() => this.handleReplyTo()}>Reply</a></div>
                </div>
                <div className={styles.nested}>
                    {this.props.nested.map((e: CommentSchema) => {
                        return <Comment key={e.id} id={e.id} contents={e.contents} gravatarUrl={e.gravatarUrl}
                                        username={e.username} nested={e.children} level={this.props.level + 1}
                                        createdTime={e.createdAt} replyTo={this.props.replyTo}/>
                    })}
                </div>
            </div>
        );
    }
}

Comment.propTypes = {
    loading: PropTypes.bool,
    id: PropTypes.any,
    className: PropTypes.string,
    gravatarUrl: PropTypes.string,
    username: PropTypes.string,
    contents: PropTypes.string,
    nested: PropTypes.array,
    createdTime: PropTypes.any,
    level: PropTypes.number,
    replyTo: PropTypes.func
};

export default Comment;