import React from 'react';

import './PostSnippet.css'
import PostTags from '../../Post/PostHeader/PostTags/PostTags.js';
import MathRenderer from '../../Post/PostContent/MathRenderer/MathRenderer';
import {Link} from 'react-router-dom'
import {Text} from '@blueprintjs/core';

class PostSnippet extends React.Component {
    getTitleBlock() {
        if (!this.props.post.title) {
            return (
                <div className={'skeleton-container'}>
                    <h1 className={'pt-skeleton title'}>Lorem ipsum dolor sit amet</h1>
                </div>
            );
        }
        return <Link to={'/posts/' + this.props.post.slug}><h1 className="title">{this.props.post.title}</h1></Link>
    }

    getContentBlock() {
        if (!this.props.post.contents) {
            return (<Text className={'pt-skeleton'}>
                {'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ac pharetra est, quis venenatis dui.' +
                ' Etiam eros purus, accumsan sed risus eget, pulvinar lobortis odio. Integer mattis a sem vel molestie. Quisque'}
            </Text>)
        }
        return (
            <Text>
                <MathRenderer source={this.props.post.overview}/>
            </Text>
        );
    }

    render() {
        return (
            <div className={'snippet-container ' + this.props.className ? this.props.className : ''}>
                {this.getTitleBlock()}
                <PostTags className="post-tags" tags={this.props.post.tags}/>
                {this.getContentBlock()}
            </div>
        )
    }
}

export default PostSnippet;