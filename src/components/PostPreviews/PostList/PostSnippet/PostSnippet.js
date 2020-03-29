import React from 'react';

import PropTypes from 'prop-types';

import {Link} from 'react-router-dom';
import PostMeta from '../../../Post/PostHeader/PostMeta/PostMeta';
import PostTags from '../../../Post/PostHeader/PostTags/PostTags';

import styles from './PostSnippet.module.css';
import Skeleton from '../../../util/Skeleton/Skeleton';
import PostContent from '../../../Post/PostContent/PostContent';

class PostSnippet extends React.Component {
    getContentBlock() {
        if (!this.props.post || !this.props.post.overview) {
            return (
                <Skeleton className={styles.contentSkeleton}>
                    {' '}
                </Skeleton>
            );
        }
        return (
            <span className={styles.snippetText}>
                <PostContent content={this.props.post.overview}/> {' '}
                <Link to={`/blog/posts/${this.props.post.slug}`} className={styles.continue}>
                    Continue Reading
                </Link>
            </span>
        );
    }

    render() {
        if (!this.props.post) {
            return (
                <div className={this.props.className ? this.props.className : ''}>
                    <div className={styles.snippetTitle}>
                        <Skeleton>
                            Lorem ipsum dolor
                        </Skeleton>
                    </div>
                    <PostMeta containerClassName={styles.authorContainer}
                              className={styles.author}
                              loading={true}
                    />
                    <PostTags/>
                    {this.getContentBlock()}
                </div>
            )

        }
        return (
            <div className={this.props.className ? this.props.className : ''}>
                <Link to={`/blog/posts/${this.props.post.slug}`} className={styles.snippetTitle}>
                    {this.props.post.draft === true ? <small>draft</small> : null} {this.props.post.title}
                </Link>
                <PostMeta containerClassName={styles.authorContainer}
                          className={styles.author}
                          author={this.props.post.author}
                          createdTime={this.props.post.createdAt}
                          modifiedTime={this.props.post.updatedAt}
                />
                <PostTags tags={this.props.post.tags}/>
                {this.getContentBlock()}
            </div>
        )
    }
}

PostSnippet.propTypes = {
    post: PropTypes.any,
    className: PropTypes.string
};

export default PostSnippet;