import React from 'react';

import PropTypes from 'prop-types';

import {Text} from '@blueprintjs/core';
import {Link} from 'react-router-dom';
import PostMeta from '../../../Post/PostHeader/PostAuthor/PostMeta';
import PostTags from '../../../Post/PostHeader/PostTags/PostTags';
import MathRenderer from '../../../Post/PostContent/MathRenderer/MathRenderer';
import {css, StyleSheet} from 'aphrodite';

import './PostSnippet.css';

class PostSnippet extends React.Component {
    getContentBlock() {
        if (!this.props.post.overview) {
            return (<Text className={'bp3-skeleton'}>
                {'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ac pharetra est, quis venenatis dui.' +
                ' Etiam eros purus, accumsan sed risus eget, pulvinar lobortis odio. Integer mattis a sem vel molestie. Quisque'}
            </Text>)
        }
        return (
            <span className={'snippetText'}>
                <MathRenderer source={this.props.post.overview}/> {' '}
                <Link to={`/posts/${this.props.post.slug}`} className={css(styles.continue)}>
                    <span>Continue Reading <span className={css(styles.arrow)}>→</span></span></Link>
            </span>
        );
    }

    render() {
        return (
            <div className={'snippet-container ' + this.props.className ? this.props.className : ''}>
                <Link to={'/posts/' + this.props.post.slug} className={css(styles.snippetTitle)}>
                    {this.props.post.title}
                </Link>
                <PostMeta containerClassName={css(styles.authorContainer)}
                          className={css(styles.author)}
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

const styles = StyleSheet.create({
    snippetTitle: {
        fontFamily: 'Dosis, sans-serif',
        fontSize: '56px',
        fontWeight: 'lighter',
        lineHeight: '80px',
        marginTop: '35px',
        marginBottom: '25px'
    },
    authorContainer: {},
    author: {},
    continue: {
        fontWeight: '300',
        fontSize: '18px',
        marginBottom: '3px',
        '@media (max-width: 600px)': {
            position: 'absolute',
            bottom: '0px',
            left: '0',
            background: 'linear-gradient(180deg, rgba(255,255,255,0) 0%, rgba(255,255,255,0.7) 26%, rgba(255,255,255,0.8) 70%)',
            width: '100%',
            textAlign: 'center',
            padding: '15px',
            margin: 0,
            fontWeight: 'bold'
        }
    },
    arrow: {
        fontSize: '22px',
        '@media (max-width: 600px)': {
            display: 'none'
        }
    }
});

console.log(styles);

export default PostSnippet;