import React from 'react';

import PropTypes from 'prop-types';

import {Text} from '@blueprintjs/core';
import {Link} from 'react-router-dom';
import PostMeta from '../../../Post/PostHeader/PostAuthor/PostMeta';
import PostTags from '../../../Post/PostHeader/PostTags/PostTags';
import MathRenderer from '../../../Post/PostContent/MathRenderer/MathRenderer';

import styles from './PostSnippet.module.css';

class PostSnippet extends React.Component {
    getContentBlock() {
        if (!this.props.post.overview) {
            return (<Text className={'bp3-skeleton'}>
                {'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ac pharetra est, quis venenatis dui.' +
                ' Etiam eros purus, accumsan sed risus eget, pulvinar lobortis odio. Integer mattis a sem vel molestie. Quisque'}
            </Text>)
        }
        return (
            <span className={styles.snippetText}>
                <MathRenderer source={this.props.post.overview}/> {' '}
                <Link to={`/posts/${this.props.post.slug}`} className={styles.continue}>
                    <span>Continue Reading <span className={styles.arrow}>→</span></span></Link>
            </span>
        );
    }

    render() {
        return (
            <div className={this.props.className ? this.props.className : ''}>
                <Link to={'/posts/' + this.props.post.slug} className={styles.snippetTitle}>
                    {this.props.post.title}
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
    post: PropTypes.any.isRequired,
    className: PropTypes.string
};

export default PostSnippet;